#!/usr/bin/env bash
# investigate.sh — analyst side. Run in CloudShell AFTER the pipeline captured evidence.
#   bash investigate.sh <evidence-bucket> <IR-id>
# Pulls the evidence, verifies hashes, then mines the memory image and live-response
# for indicators of compromise. Writes findings into ./<IR-id>/findings/.
set -euo pipefail
BUCKET="${1:?usage: investigate.sh <bucket> <IR-id>}"
INC="${2:?usage: investigate.sh <bucket> <IR-id>}"
D="$INC"; mkdir -p "$D/findings"; cd "$D"

echo "[*] Downloading evidence for $INC"
aws s3 cp "s3://$BUCKET/incidents/$INC/" . --recursive --only-show-errors

echo "[*] Verifying evidence integrity (hashes recorded at capture time)"
sha256sum -c SHA256SUMS | tee findings/integrity-check.txt

# The attacker's own cleanup (blanked history) doesn't reach RAM: strings from the
# memory image recover what ran. Carve printable strings once, then grep for IOCs.
echo "[*] Carving strings from memory image"
strings -a -t d memory.lime > memory.strings 2>/dev/null || strings -a memory.lime > memory.strings

grep_save () { echo "== $1 =="; grep -aiE "$2" "$3" | sort -u | head -n "${4:-40}"; echo; }

{
  grep_save "Suspicious paths (/tmp hidden dirs, dropped binaries)" \
            '/tmp/\.[a-z]|kworkerd' memory.strings 30
  grep_save "Candidate C2 / beacon indicators" \
            'gate\.php|198\.51\.100\.23|/gate\.|beacon' memory.strings 30
  grep_save "Persistence artifacts" \
            'cron\.d/system-update|kworkerd\.service|authorized_keys|backup-svc' memory.strings 30
  grep_save "Attacker SSH key" \
            'ssh-ed25519.*attacker@evil|SIMULATED' memory.strings 10
} > findings/memory-iocs.txt

echo "[*] Cross-checking against live-response (process + network state at capture)"
{
  echo "== processes matching the dropped payload =="; grep -aiE 'kworkerd|/tmp/\.x' live-response.txt || echo "none in process list"
  echo; echo "== network connections to the C2 =="; grep -aiE '198\.51\.100\.23|gate\.php' live-response.txt || echo "none in connection list"
  echo; echo "== cron / persistence seen on disk at capture =="; grep -aiE 'system-update|kworkerd' live-response.txt || echo "none"
} > findings/live-response-iocs.txt

echo
echo "[+] Done. Review:"
echo "    $D/findings/integrity-check.txt"
echo "    $D/findings/memory-iocs.txt"
echo "    $D/findings/live-response-iocs.txt"
echo "    ledger.jsonl  (run verify_ledger.py on it)"
