from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

LEDGER_DIR = ".anchor"
LEDGER_FILE = "ledger.jsonl"
HEAD_FILE = "HEAD"
ANCHOR_FILE = "anchors.log"
GENESIS_PREV = "0" * 64
SOURCE_TYPES = ("tool_output", "manual", "document", "network", "external_report", "code_read")
CONFIDENCES = ("high", "medium", "low")
CLAIM_STATUSES = ("supported", "contradicted", "unverified")
BLOCKING_STATUSES = ("supported", "contradicted")


class LedgerError(Exception):
    pass


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def compute_hash(record):
    body = {k: record[k] for k in ("seq", "ts", "type", "payload", "prev")}
    return sha256_hex(canonical_bytes(body))


def ledger_paths(root):
    d = pathlib.Path(root) / LEDGER_DIR
    return d / LEDGER_FILE, d / HEAD_FILE


def load_records(ledger_path):
    if not ledger_path.exists():
        return []
    records = []
    with ledger_path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LedgerError(f"corrupt ledger at line {lineno}: {exc}") from exc
    return records


def append_record(ledger_path, head_path, rec_type, payload):
    records = load_records(ledger_path)
    prev = records[-1]["hash"] if records else GENESIS_PREV
    record = {
        "seq": len(records) + 1,
        "ts": now_iso(),
        "type": rec_type,
        "payload": payload,
        "prev": prev,
    }
    record["hash"] = compute_hash(record)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    head_path.write_text(record["hash"] + "\n", encoding="utf-8")
    return record


def verify_chain(ledger_path, head_path):
    records = load_records(ledger_path)
    problems = []
    prev = GENESIS_PREV
    for idx, rec in enumerate(records, 1):
        try:
            expected = compute_hash(rec)
        except KeyError as exc:
            problems.append(f"seq {idx}: missing field {exc}")
            continue
        if rec.get("seq") != idx:
            problems.append(f"seq {idx}: unexpected seq value {rec.get('seq')}")
        if rec.get("prev") != prev:
            problems.append(f"seq {idx}: prev does not match preceding hash")
        if rec.get("hash") != expected:
            problems.append(f"seq {idx}: content hash mismatch")
        prev = rec.get("hash")
    head = head_path.read_text(encoding="utf-8").strip() if head_path.exists() else None
    if records and head != records[-1]["hash"]:
        problems.append("HEAD does not match last record (truncation or external edit)")
    return records, problems


def unique_id(prefix, seed, taken):
    for n in range(1000):
        cand = prefix + sha256_hex(f"{seed}|{n}".encode("utf-8"))[:10]
        if cand not in taken:
            return cand
    raise LedgerError("could not allocate a unique id")


def check_claims(records):
    evidence = {r["payload"]["id"]: r["payload"] for r in records if r["type"] == "evidence"}
    blocking, warnings = [], []
    for rec in records:
        if rec["type"] != "claim":
            continue
        c = rec["payload"]
        if c["status"] in BLOCKING_STATUSES:
            if not c["evidence"]:
                blocking.append(f"{c['id']}: status '{c['status']}' has no evidence")
            for eid in c["evidence"]:
                if eid not in evidence:
                    blocking.append(f"{c['id']}: references unknown evidence '{eid}'")
            levels = [evidence[e]["confidence"] for e in c["evidence"] if e in evidence]
            if levels and all(lvl == "low" for lvl in levels):
                warnings.append(f"{c['id']}: only low-confidence evidence backs a '{c['status']}' claim")
        elif c["status"] == "unverified" and c["evidence"]:
            warnings.append(f"{c['id']}: marked unverified but has evidence attached")
    return blocking, warnings


def cmd_init(args, paths):
    ledger_path, _ = paths
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"initialized: {ledger_path}" if not ledger_path.exists() else f"already initialized: {ledger_path}")


def cmd_evidence_add(args, paths):
    ledger_path, head_path = paths
    records = load_records(ledger_path)
    taken = {r["payload"]["id"] for r in records if r["type"] == "evidence"}
    artifacts = []
    for raw in args.artifact:
        p = pathlib.Path(raw)
        if not p.is_file():
            raise LedgerError(f"artifact not found: {raw}")
        data = p.read_bytes()
        artifacts.append({"path": str(p), "sha256": sha256_hex(data), "bytes": len(data)})
    stamp = now_iso()
    seed = f"{args.tool}|{args.observation}|{stamp}"
    payload = {
        "id": unique_id("ev-", seed, taken),
        "tool": args.tool,
        "invocation": args.invocation,
        "observation": args.observation,
        "source_type": args.source_type,
        "confidence": args.confidence,
        "artifacts": artifacts,
        "operator": args.operator,
        "tags": args.tag,
        "captured_at": stamp,
    }
    rec = append_record(ledger_path, head_path, "evidence", payload)
    print(payload["id"])
    print(f"seq={rec['seq']} hash={rec['hash']}", file=sys.stderr)


def cmd_evidence_list(args, paths):
    ledger_path, _ = paths
    for rec in load_records(ledger_path):
        if rec["type"] != "evidence":
            continue
        p = rec["payload"]
        print(f"{p['id']}  {p['confidence']:<6} {p['tool']:<14} {p['observation'][:80]}")


def cmd_claim_add(args, paths):
    ledger_path, head_path = paths
    records = load_records(ledger_path)
    evidence_ids = {r["payload"]["id"] for r in records if r["type"] == "evidence"}
    missing = [e for e in args.evidence if e not in evidence_ids]
    if missing:
        raise LedgerError("unknown evidence id(s): " + ", ".join(missing))
    if args.status in BLOCKING_STATUSES and not args.evidence:
        raise LedgerError(f"status '{args.status}' requires at least one --evidence id")
    taken = {r["payload"]["id"] for r in records if r["type"] == "claim"}
    payload = {
        "id": unique_id("cl-", args.statement, taken),
        "statement": args.statement,
        "status": args.status,
        "confidence": args.confidence,
        "evidence": args.evidence,
        "caveats": args.caveat,
    }
    append_record(ledger_path, head_path, "claim", payload)
    print(payload["id"])


def cmd_claim_list(args, paths):
    ledger_path, _ = paths
    for rec in load_records(ledger_path):
        if rec["type"] != "claim":
            continue
        p = rec["payload"]
        print(f"{p['id']}  {p['status']:<12} {p['confidence']:<6} {p['statement'][:80]}")


def cmd_verify(args, paths):
    ledger_path, head_path = paths
    records, problems = verify_chain(ledger_path, head_path)
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        print(f"chain FAILED ({len(problems)} problem(s), {len(records)} records)", file=sys.stderr)
        return 2
    print(f"chain OK ({len(records)} records)")
    return 0


def cmd_check(args, paths):
    ledger_path, head_path = paths
    records, chain_problems = verify_chain(ledger_path, head_path)
    blocking, warnings = check_claims(records)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    if chain_problems or blocking:
        for p in chain_problems + blocking:
            print(f"FAIL: {p}", file=sys.stderr)
        print("gate BLOCKED", file=sys.stderr)
        return 2
    print("gate PASS")
    return 0


def cmd_report(args, paths):
    ledger_path, head_path = paths
    records, chain_problems = verify_chain(ledger_path, head_path)
    blocking, warnings = check_claims(records)
    evidence = {r["payload"]["id"]: r["payload"] for r in records if r["type"] == "evidence"}
    claims = [r["payload"] for r in records if r["type"] == "claim"]

    out = ["# anchor — Audit Report", ""]
    out.append(f"- Generated: {now_iso()}")
    out.append(f"- Records: {len(records)} ({len(evidence)} evidence, {len(claims)} claims)")
    out.append(f"- Chain: {'VERIFIED' if not chain_problems else 'FAILED'}")
    out.append(f"- Gate: {'PASS' if not chain_problems and not blocking else 'BLOCKED'}")
    out.append("")

    for status, title in (("supported", "Supported claims"),
                          ("contradicted", "Contradicted claims"),
                          ("unverified", "Unverified claims (not relied upon)")):
        out.append(f"## {title}")
        out.append("")
        subset = [c for c in claims if c["status"] == status]
        if not subset:
            out.append("_None._")
            out.append("")
            continue
        for c in subset:
            out.append(f"### `{c['id']}` — {c['status']} (confidence: {c['confidence']})")
            out.append("")
            out.append(f"> {c['statement']}")
            out.append("")
            if c["evidence"]:
                out.append("Evidence:")
                for eid in c["evidence"]:
                    ev = evidence.get(eid)
                    if not ev:
                        out.append(f"- `{eid}` — **missing from ledger**")
                        continue
                    out.append(f"- `{eid}` ({ev['tool']}, {ev['source_type']}, {ev['confidence']})")
                    out.append(f"  - {ev['observation']}")
                    if ev.get("invocation"):
                        out.append(f"  - invocation: `{ev['invocation']}`")
                    for a in ev.get("artifacts", []):
                        out.append(f"  - artifact: `{a['path']}` sha256 `{a['sha256']}`")
            if c["caveats"]:
                out.append("")
                out.append("Caveats:")
                for cav in c["caveats"]:
                    out.append(f"- {cav}")
            out.append("")

    if warnings:
        out.append("## Warnings")
        out.append("")
        for w in warnings:
            out.append(f"- {w}")
        out.append("")
    if chain_problems or blocking:
        out.append("## Blocking issues")
        out.append("")
        for p in chain_problems + blocking:
            out.append(f"- {p}")
        out.append("")
    print("\n".join(out))


def cmd_stamp(args, paths):
    _, head_path = paths
    if not head_path.exists():
        raise LedgerError("nothing to stamp; ledger is empty")
    head = head_path.read_text(encoding="utf-8").strip()
    anchor_path = head_path.parent / ANCHOR_FILE
    anchor_path.parent.mkdir(parents=True, exist_ok=True)
    with anchor_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{now_iso()} {head}\n")
        fh.flush()
        os.fsync(fh.fileno())
    print(head)


def build_parser():
    p = argparse.ArgumentParser(prog="anchor")
    p.add_argument("--root", default=".", help="project root containing .anchor/")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")

    ev = sub.add_parser("evidence")
    evs = ev.add_subparsers(dest="ev_cmd", required=True)
    eadd = evs.add_parser("add")
    eadd.add_argument("--tool", required=True)
    eadd.add_argument("--observation", required=True)
    eadd.add_argument("--invocation", default="")
    eadd.add_argument("--source-type", default="tool_output", choices=SOURCE_TYPES)
    eadd.add_argument("--confidence", default="high", choices=CONFIDENCES)
    eadd.add_argument("--artifact", action="append", default=[])
    eadd.add_argument("--operator", default=os.environ.get("USER", "unknown"))
    eadd.add_argument("--tag", action="append", default=[])
    evs.add_parser("list")

    cl = sub.add_parser("claim")
    cls = cl.add_subparsers(dest="cl_cmd", required=True)
    cadd = cls.add_parser("add")
    cadd.add_argument("--statement", required=True)
    cadd.add_argument("--status", default="unverified", choices=CLAIM_STATUSES)
    cadd.add_argument("--confidence", default="medium", choices=CONFIDENCES)
    cadd.add_argument("--evidence", action="append", default=[])
    cadd.add_argument("--caveat", action="append", default=[])
    cls.add_parser("list")

    sub.add_parser("verify")
    sub.add_parser("check")
    sub.add_parser("report")
    sub.add_parser("stamp")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    paths = ledger_paths(args.root)
    if args.cmd == "evidence":
        key = ("evidence", args.ev_cmd)
    elif args.cmd == "claim":
        key = ("claim", args.cl_cmd)
    else:
        key = (args.cmd,)
    handlers = {
        ("init",): cmd_init,
        ("evidence", "add"): cmd_evidence_add,
        ("evidence", "list"): cmd_evidence_list,
        ("claim", "add"): cmd_claim_add,
        ("claim", "list"): cmd_claim_list,
        ("verify",): cmd_verify,
        ("check",): cmd_check,
        ("report",): cmd_report,
        ("stamp",): cmd_stamp,
    }
    handler = handlers.get(key)
    if handler is None:
        print(f"unknown command: {key}", file=sys.stderr)
        return 2
    try:
        return handler(args, paths) or 0
    except LedgerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
