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
GENESIS_PREV = "0" * 64
SOURCE_TYPES = ("tool_output", "manual", "document", "network", "external_report", "code_read")
CONFIDENCES = ("high", "medium", "low")

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

    sub.add_parser("verify")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    paths = ledger_paths(args.root)
    if args.cmd == "evidence":
        key = ("evidence", args.ev_cmd)
    else:
        key = (args.cmd,)
    handlers = {
        ("init",): cmd_init,
        ("evidence", "add"): cmd_evidence_add,
        ("evidence", "list"): cmd_evidence_list,
        ("verify",): cmd_verify,
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
