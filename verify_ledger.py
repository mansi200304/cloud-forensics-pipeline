"""
verify_ledger.py: prove a chain-of-custody ledger has not been altered.

Usage (in AWS CloudShell or locally):
    aws s3 cp s3://<evidence-bucket>/incidents/<IR-id>/ledger.jsonl .
    python3 verify_ledger.py ledger.jsonl

Checks, for every record:
  1. its record_hash matches a fresh SHA-256 of its own contents
  2. its prev_hash equals the record_hash of the record before it
  3. sequence numbers have no gaps
Prints the head hash. Publish that hash outside AWS (for example in a GitHub
commit) and anyone can later prove the ledger still matches it.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def verify(path: str) -> bool:
    with open(path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    if not records:
        print("Ledger is empty.")
        return False

    expected_prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k != "record_hash"}
        recomputed = hashlib.sha256(canonical(body).encode()).hexdigest()
        problems = []
        if rec.get("seq") != i:
            problems.append(f"sequence gap (expected {i}, found {rec.get('seq')})")
        if rec.get("prev_hash") != expected_prev:
            problems.append("broken link to previous record")
        if recomputed != rec.get("record_hash"):
            problems.append("contents were modified")
        status = "OK " if not problems else "FAIL"
        print(f"[{status}] #{i:<3} {rec.get('action', '?'):<24} {rec.get('record_hash', '')[:16]}…"
              + (f"  <- {'; '.join(problems)}" if problems else ""))
        if problems:
            print("\nChain of custody BROKEN.")
            return False
        expected_prev = rec["record_hash"]

    print(f"\nChain of custody intact: {len(records)} records.")
    print(f"Head hash: {expected_prev}")
    return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 verify_ledger.py ledger.jsonl")
    sys.exit(0 if verify(sys.argv[1]) else 1)
