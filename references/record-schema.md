# Record schema

## Ledger line format

One JSON object per line in `.anchor/ledger.jsonl`. Keys sorted, UTF-8, newline-terminated.

```json
{
  "seq": 1,
  "ts": "2026-11-19T09:14:02Z",
  "type": "evidence",
  "payload": { "...": "..." },
  "prev": "0000000000000000000000000000000000000000000000000000000000000000",
  "hash": "<sha256 of canonical(seq,ts,type,payload,prev)>"
}
```

`hash` covers the record's own fields plus `prev`, so altering any byte of any record
breaks every subsequent link.

## Evidence payload

```json
{
  "id": "ev-1a2b3c4d5e",
  "tool": "nmap",
  "invocation": "nmap -sV -p22,80,443 10.0.0.5",
  "observation": "22/tcp open ssh OpenSSH 8.9p1; 443/tcp open https nginx 1.24.0",
  "source_type": "tool_output",
  "confidence": "high",
  "artifacts": [
    { "path": "scan.xml", "sha256": "9f2c...", "bytes": 18342 }
  ],
  "operator": "analyst",
  "tags": ["recon", "external"],
  "captured_at": "2026-11-19T09:13:55Z"
}
```

## Claim payload

```json
{
  "id": "cl-7d8e9f0a1b",
  "statement": "Host 10.0.0.5 exposes SSH (OpenSSH 8.9p1) on 22/tcp",
  "status": "supported",
  "confidence": "high",
  "evidence": ["ev-1a2b3c4d5e"],
  "caveats": ["scan performed from a single vantage point"]
}
```

## Invariants enforced by the CLI

1. `prev` must equal the previous record's `hash`; the first record uses `GENESIS_PREV`.
2. `hash` must equal the recomputed canonical hash.
3. `.anchor/HEAD` must equal the last record's `hash`.
4. `supported` and `contradicted` claims must reference at least one evidence id.
5. Every referenced evidence id must exist in the ledger.

Violating 1–3 makes `verify` exit 2. Violating 4–5 makes `check` exit 2.
