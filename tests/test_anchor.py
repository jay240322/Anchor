import json
import pathlib
import subprocess
import sys

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "anchor.py"


def run(root, *args, check=True):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *args],
        capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"{args} failed: {proc.stderr}")
    return proc


def test_evidence_add_and_verify(tmp_path):
    run(tmp_path, "init")
    ev = run(tmp_path, "evidence", "add", "--tool", "nmap",
             "--observation", "22/tcp open ssh").stdout.strip()
    assert ev.startswith("ev-")
    assert run(tmp_path, "verify").returncode == 0


def test_tamper_detected(tmp_path):
    run(tmp_path, "init")
    run(tmp_path, "evidence", "add", "--tool", "t", "--observation", "o")
    ledger = tmp_path / ".anchor" / "ledger.jsonl"
    rec = json.loads(ledger.read_text().splitlines()[0])
    rec["payload"]["observation"] = "tampered"
    ledger.write_text(json.dumps(rec) + "\n")
    assert run(tmp_path, "verify", check=False).returncode == 2


def test_truncation_detected(tmp_path):
    run(tmp_path, "init")
    run(tmp_path, "evidence", "add", "--tool", "t", "--observation", "one")
    run(tmp_path, "evidence", "add", "--tool", "t", "--observation", "two")
    ledger = tmp_path / ".anchor" / "ledger.jsonl"
    ledger.write_text(ledger.read_text().splitlines()[0] + "\n")
    assert run(tmp_path, "verify", check=False).returncode == 2
