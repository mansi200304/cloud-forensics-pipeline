# Cloud Forensics Pipeline for Amazon EC2

Automated, serverless incident response for EC2: a GuardDuty finding triggers
evidence preservation, a disk snapshot, live memory capture, and host isolation —
every action written to a **tamper-evident chain-of-custody ledger**. Captured
memory is then analysed to recover indicators of compromise.

Built and tested in an AWS Academy Learner Lab to understand, hands-on, how a
Security Operations Center automates the first minutes of a cloud intrusion.

> **Prior art, stated honestly.** AWS publishes a production reference design,
> [Automated Forensics Orchestrator for Amazon EC2 and EKS](https://aws.amazon.com/solutions/guidance/automated-forensics-orchestrator-for-amazon-ec2-and-eks/).
> I studied its approach and built a minimal version myself to learn each step.
> What I added on top of the reference pattern: a hash-chained custody ledger with
> an independent verifier, a strict instance-scope safety guard, and a full
> attack → capture → investigate case study on a single low-cost instance.

## Why this order

Evidence is collected in order of volatility, so a later step can't contaminate
an earlier one:

1. **Preserve** — enable termination protection, set shutdown-behaviour to *stop*
   (stopping preserves the EBS volume; terminating can destroy it), tag the incident.
2. **Snapshot disk** — point-in-time EBS snapshot, taken from outside the guest.
3. **Capture memory** — AVML over SSM Run Command, with live triage (processes,
   network connections, logins, cron). Runs *before* isolation, because it needs
   the network. The acquisition tool's hash is verified on the host before it runs.
4. **Isolate** — move the instance to a no-ingress / no-egress quarantine security
   group.

## Architecture

```
            ┌──────────────┐   finding    ┌──────────────┐   invoke   ┌─────────────────┐
 attacker → │  EC2 (victim)│ ───────────► │  GuardDuty   │ ─────────► │  EventBridge    │
            └──────┬───────┘              └──────────────┘            └────────┬────────┘
                   │ SSM Run Command (AVML + triage)                           │
                   ▼                                                           ▼
            ┌──────────────┐    put evidence + hash-chained ledger    ┌─────────────────┐
            │  S3 evidence │ ◄─────────────────────────────────────── │ Lambda          │
            │  bucket      │                                          │ fl-responder    │
            │  (versioned) │        snapshot / isolate / tag          │ (LabRole)       │
            └──────────────┘ ◄─────────────────────────────────────── └─────────────────┘
```

## Chain of custody

Every action appends a record to `ledger.jsonl` (JSON Lines in S3). Each record
stores the SHA-256 of the record before it, so altering or deleting any entry
breaks the chain. `verify_ledger.py` recomputes every hash and link and prints the
head hash; publish that hash (e.g. in a commit) and anyone can later prove the
ledger is unchanged. Each evidence file's own SHA-256 is recorded the moment it is
captured on the host.

## Results (sample run)

| Metric | Value |
|---|---|
| Time from finding to first evidence preserved | under 10 seconds |
| Evidence captured | 1 GB memory image, EBS snapshot, live-response, metadata |
| Chain-of-custody records per incident | ~10, all verified |
| IOCs recovered from memory **after** the attacker wiped bash history | dropped binary path, C2 indicator, 3 persistence mechanisms, backdoor user, implanted SSH key |

See [`INCIDENT-REPORT.md`](INCIDENT-REPORT.md) for the full investigation.

## Repo contents

| File | Purpose |
|---|---|
| `lambda_function.py` | The responder: preserve, snapshot, capture, isolate, log |
| `verify_ledger.py` | Independent chain-of-custody verifier |
| `simulate_intrusion.sh` | Safe post-compromise attacker, for the case study |
| `investigate.sh` | Analyst toolkit: pull evidence, verify, extract IOCs |
| `test_event.json` | GuardDuty-shaped event for manual testing |
| `SETUP.md` | Step-by-step build in an AWS Academy Learner Lab |
| `INCIDENT-REPORT.md` | The investigation write-up |

## Safety and scope

- Built for a disposable lab account; the responder **only acts on instances tagged
  `Project=forensics-lab`** and ignores everything else.
- `simulate_intrusion.sh` is harmless: it touches only its own host, downloads
  nothing, and destroys nothing. The "C2" address is in the documentation-only
  `198.51.100.0/24` range (RFC 5737).
- Not production code. A real deployment would use a dedicated forensic account,
  cross-account roles, S3 Object Lock for write-once storage, and KMS encryption.

## Skills demonstrated

Incident response · digital forensics · memory & disk acquisition · AWS (GuardDuty,
EventBridge, Lambda, EC2, EBS, S3, Systems Manager, CloudTrail) · chain of custody ·
IOC analysis · Python · Bash · serverless automation.
