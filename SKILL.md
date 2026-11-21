---
name: anchor
description: Anchors every cybersecurity research finding to a hashed, tamper-evident evidence record so the claim is verifiable and replayable. Blocks final reports whose claims are not backed by recorded evidence.
license: MIT
---

# anchor

## When to use

- Any tool invocation whose output you will later rely on in a finding.
- Negative results (failed commands, absent strings, filtered ports) — these are evidence too.
- Manual observations from reading code, transcripts, or documents.
- Producing vulnerability findings, CTI assessments, or detection-rule reviews that a reviewer must verify.

## When not to use

- Pure exploration where nothing will be reported.
- Tasks with no factual claims.

## Workflow

Assume `ANCHOR="python3 scripts/anchor.py --root ."` and run from the project root.

1. Initialize once per engagement:

   ```bash
   $ANCHOR init
   ```

2. Record evidence as you collect it. Capture the printed `ev-` id:

   ```bash
   $ANCHOR evidence add \
     --tool nmap \
     --invocation "nmap -sV -p22,80,443 10.0.0.5" \
     --observation "22/tcp open ssh OpenSSH 8.9p1" \
     --artifact scan.xml \
     --confidence high
   ```

3. Verify chain integrity at any time:

   ```bash
   $ANCHOR verify     # exit 0 = OK, exit 2 = tamper
   ```

## Claims and the gate

Every factual assertion in a final report becomes a claim. Do not deliver the report if
`$ANCHOR check` does not print `gate PASS`.

```bash
$ANCHOR claim add \
  --statement "Host 10.0.0.5 exposes SSH (OpenSSH 8.9p1) on 22/tcp" \
  --status supported \
  --confidence high \
  --evidence ev-xxxxxxxxxx
```

Status values:
- `supported` — direct evidence exists. Blocking.
- `contradicted` — evidence refutes the statement. Blocking; must be reported.
- `unverified` — no evidence yet. Non-blocking, appears in a labeled report section.

Then run the gate and emit the report:

```bash
$ANCHOR check                # exit 2 = blocked
$ANCHOR report > FINDINGS.md
```

## Record contract (evidence)

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `ev-` + 10 hex, generated |
| `tool` | yes | Source name |
| `observation` | yes | What was actually seen, verbatim |
| `source_type` | yes | `tool_output` \| `manual` \| `document` \| `network` \| `external_report` \| `code_read` |
| `confidence` | yes | `high` \| `medium` \| `low` |
| `artifacts` | no | Hashed automatically |
| `operator` | yes | Who captured it |
| `captured_at` | yes | ISO-8601 UTC |

## Record contract (claim)

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `cl-` + 10 hex, generated |
| `statement` | yes | One falsifiable sentence |
| `status` | yes | `supported` \| `contradicted` \| `unverified` |
| `confidence` | yes | `high` \| `medium` \| `low` |
| `evidence` | conditional | Required for `supported` and `contradicted` |
| `caveats` | no | Scope limits, assumptions |

Full schema: `references/record-schema.md`.

## Graceful degradation

- No `python3`? Hand-write `.anchor/ledger.jsonl` in the same format and say so in the report. Never fabricate hashes.
- `verify` exits 2? Stop. Report the divergence; do not append to a broken chain.
