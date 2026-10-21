"""
fl-responder: automated forensic response for EC2 (preserve, capture, contain)

Trigger : EventBridge rule on GuardDuty findings for EC2 instances
Runtime : Python 3.12, execution role = LabRole (AWS Academy Learner Lab)

Order of operations follows the order of volatility (RFC 3227):
    1. record the finding         -> custody ledger
    2. preserve instance metadata -> S3 + ledger
    3. snapshot every EBS volume  -> point-in-time, taken from outside the guest,
                                     so the capture tool in step 4 can't contaminate it
    4. capture memory + live triage via SSM -> S3 + ledger (CAPTURE_MEMORY=true)
    5. isolate the instance       -> quarantine security group (ISOLATE=true)

Every action is appended to a hash-chained ledger (ledger.jsonl): each record
stores the SHA-256 of the previous record, so editing or deleting any entry
breaks the chain. Verify it with verify_ledger.py.
"""
import datetime
import hashlib
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
QUARANTINE_SG = os.environ["QUARANTINE_SG"]
ISOLATE = os.environ.get("ISOLATE", "false").lower() == "true"
CAPTURE_MEMORY = os.environ.get("CAPTURE_MEMORY", "false").lower() == "true"
AVML_SHA256 = os.environ.get("AVML_SHA256", "")          # expected hash of tools/avml in the bucket
CAPTURE_TIMEOUT = int(os.environ.get("CAPTURE_TIMEOUT", "600"))

# Safety guard: the pipeline only ever touches instances carrying this tag.
SCOPE_TAG = ("Project", "forensics-lab")

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
ssm = boto3.client("ssm")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def canonical(obj) -> str:
    """Deterministic JSON so the same record always hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Ledger:
    """Append-only, hash-chained chain-of-custody log stored in S3 as JSON Lines."""

    GENESIS = "0" * 64

    def __init__(self, incident_id: str):
        self.key = f"incidents/{incident_id}/ledger.jsonl"
        self.records = []
        try:
            body = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=self.key)["Body"].read().decode()
            self.records = [json.loads(line) for line in body.splitlines() if line.strip()]
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                raise

    @property
    def head(self) -> str:
        return self.records[-1]["record_hash"] if self.records else self.GENESIS

    def append(self, action: str, detail: dict, artifact_sha256: str | None = None) -> str:
        record = {
            "seq": len(self.records),
            "time": utc_now(),
            "actor": "fl-responder",
            "action": action,
            "detail": detail,
            "artifact_sha256": artifact_sha256,
            "prev_hash": self.head,
        }
        record["record_hash"] = sha256(canonical(record).encode())
        self.records.append(record)
        body = "\n".join(canonical(r) for r in self.records) + "\n"
        s3.put_object(Bucket=EVIDENCE_BUCKET, Key=self.key, Body=body.encode(),
                      ContentType="application/x-ndjson")
        print(f"[ledger] #{record['seq']} {action} -> {record['record_hash'][:16]}…")
        return record["record_hash"]


def put_evidence(incident_id: str, name: str, payload: bytes, content_type: str) -> tuple[str, str]:
    key = f"incidents/{incident_id}/{name}"
    s3.put_object(Bucket=EVIDENCE_BUCKET, Key=key, Body=payload, ContentType=content_type)
    return key, sha256(payload)


CAPTURE_SCRIPT = r"""
set -euo pipefail
INC="{incident_id}"; BUCKET="{bucket}"; WORK="/tmp/fl-$INC"
mkdir -p "$WORK" && cd "$WORK"

# Tool integrity: pull AVML from the evidence bucket and verify its hash before running it.
aws s3 cp "s3://$BUCKET/tools/avml" ./avml --only-show-errors
echo "{avml_sha256}  avml" | sha256sum -c - >/dev/null
chmod +x avml

# Live triage first: the most volatile state.
{{
  echo "== collected (UTC) =="; date -u +%Y-%m-%dT%H:%M:%SZ
  echo "== kernel =="; uname -a
  echo "== uptime =="; uptime
  echo "== logged-in users =="; who || true
  echo "== recent logins =="; last -n 20 || true
  echo "== processes =="; ps auxww --sort=start_time
  echo "== network connections =="; ss -tunap || true
  echo "== interfaces =="; ip addr
  echo "== listening services =="; ss -tlnp || true
  echo "== cron =="; ls -la /etc/cron* /var/spool/cron 2>/dev/null || true
}} > live-response.txt 2>&1

# Memory acquisition.
./avml memory.lime
uname -r > kernel-release.txt
sha256sum memory.lime live-response.txt kernel-release.txt > SHA256SUMS

for f in memory.lime live-response.txt kernel-release.txt SHA256SUMS; do
  aws s3 cp "$f" "s3://$BUCKET/incidents/$INC/$f" --only-show-errors
done
echo "MEMBYTES $(stat -c %s memory.lime)"
cat SHA256SUMS
rm -rf "$WORK"
"""


def capture_memory(instance_id: str, incident_id: str, ledger: "Ledger") -> dict:
    """Run AVML + live triage on the instance through SSM Run Command, then log the hashes."""
    script = CAPTURE_SCRIPT.format(incident_id=incident_id, bucket=EVIDENCE_BUCKET,
                                   avml_sha256=AVML_SHA256)
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Comment=f"{incident_id} memory acquisition",
        Parameters={"commands": [script], "executionTimeout": [str(CAPTURE_TIMEOUT)]},
        TimeoutSeconds=60,
    )["Command"]["CommandId"]
    ledger.append("memory_capture_started", {"ssm_command_id": cmd, "tool": "AVML",
                  "tool_sha256": AVML_SHA256})

    deadline = time.time() + CAPTURE_TIMEOUT
    status, out = "Pending", {}
    while time.time() < deadline:
        time.sleep(5)
        try:
            out = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        status = out["Status"]
        if status not in ("Pending", "InProgress", "Delayed"):
            break

    if status != "Success":
        err = (out.get("StandardErrorContent") or "")[-800:]
        ledger.append("memory_capture_failed", {"ssm_status": status, "stderr_tail": err})
        return {"ok": False, "status": status}

    hashes, size = {}, None
    for line in out.get("StandardOutputContent", "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "MEMBYTES":
            size = int(parts[1])
        elif len(parts) == 2 and len(parts[0]) == 64:
            hashes[parts[1]] = parts[0]
    for name, digest in hashes.items():
        ledger.append("evidence_collected", {"s3_key": f"incidents/{incident_id}/{name}",
                      "collected_by": "SSM/AVML" if name == "memory.lime" else "SSM",
                      **({"bytes": size} if name == "memory.lime" and size else {})}, digest)
    return {"ok": True, "hashes": hashes, "bytes": size}


def lambda_handler(event, context):
    detail = event.get("detail", {})
    finding = {
        "finding_id": detail.get("id", "manual-test"),
        "type": detail.get("type", "unknown"),
        "severity": detail.get("severity"),
        "sample": bool(detail.get("service", {}).get("additionalInfo", {}).get("sample")),
    }
    instance_id = detail.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    if not instance_id:
        return {"status": "ignored", "reason": "finding has no EC2 instance"}

    # --- Scope check: never act on anything outside the lab ---
    try:
        inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    except (ClientError, IndexError):
        # GuardDuty sample findings use fake instance IDs, so they land here.
        return {"status": "ignored", "reason": f"instance {instance_id} not found"}
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    if tags.get(SCOPE_TAG[0]) != SCOPE_TAG[1]:
        return {"status": "ignored", "reason": "instance is outside the forensics-lab scope"}
    if tags.get("IncidentId"):
        return {"status": "duplicate", "incident_id": tags["IncidentId"]}

    incident_id = datetime.datetime.now(datetime.timezone.utc).strftime("IR-%Y%m%d-%H%M%S")
    ledger = Ledger(incident_id)
    ledger.append("finding_received", {**finding, "instance_id": instance_id})

    # --- 1. Preserve: stop accidental destruction, record pre-response state ---
    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
    ec2.modify_instance_attribute(InstanceId=instance_id,
                                  InstanceInitiatedShutdownBehavior={"Value": "stop"})
    ec2.create_tags(Resources=[instance_id], Tags=[
        {"Key": "IncidentId", "Value": incident_id},
        {"Key": "ForensicStatus", "Value": "preserving"},
    ])
    key, digest = put_evidence(incident_id, "instance-metadata.json",
                               json.dumps(inst, indent=2, default=str).encode(), "application/json")
    ledger.append("metadata_preserved", {"s3_key": key,
                  "original_security_groups": [g["GroupId"] for g in inst["SecurityGroups"]],
                  "termination_protection": True}, digest)

    # --- 2. Snapshot every attached EBS volume (point-in-time, before anything runs on the guest) ---
    snapshots = []
    for bdm in inst.get("BlockDeviceMappings", []):
        volume_id = bdm.get("Ebs", {}).get("VolumeId")
        if not volume_id:
            continue
        snap = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"{incident_id} evidence {instance_id} {bdm['DeviceName']}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "IncidentId", "Value": incident_id},
                {"Key": "Project", "Value": "forensics-lab"},
                {"Key": "SourceInstance", "Value": instance_id},
            ]}],
        )
        snapshots.append(snap["SnapshotId"])
        ledger.append("disk_snapshot_started", {"volume_id": volume_id, "device": bdm["DeviceName"],
                      "snapshot_id": snap["SnapshotId"]})

    # --- 3. Memory + live triage via SSM (needs network, so it runs before isolation) ---
    memory = {"ok": False, "status": "skipped"}
    if CAPTURE_MEMORY:
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "ForensicStatus", "Value": "capturing-memory"}])
        memory = capture_memory(instance_id, incident_id, ledger)
    else:
        ledger.append("memory_capture_skipped", {"reason": "CAPTURE_MEMORY=false"})

    # --- 4. Isolate ---
    if ISOLATE:
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG])
        ledger.append("isolated", {"security_groups": [QUARANTINE_SG],
                      "note": "existing tracked connections can persist until they time out"})
    else:
        ledger.append("isolation_skipped", {"reason": "ISOLATE=false (test mode)"})

    ec2.create_tags(Resources=[instance_id], Tags=[
        {"Key": "ForensicStatus", "Value": "contained" if ISOLATE else "preserved"}])
    head = ledger.append("response_complete", {"snapshots": snapshots, "memory_captured": memory["ok"]})

    result = {"status": "ok", "incident_id": incident_id, "instance_id": instance_id,
              "isolated": ISOLATE, "snapshots": snapshots, "memory": memory, "ledger_head": head,
              "ledger": f"s3://{EVIDENCE_BUCKET}/{ledger.key}"}
    print(json.dumps(result))
    return result
