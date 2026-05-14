# CloudTrail Anomaly Alerter

A serverless AWS security monitoring tool that analyzes CloudTrail logs in real time, detects suspicious API activity, maps findings to **MITRE ATT&CK**, and emits structured JSON alerts to SNS and CloudWatch Logs for SIEM ingestion.

Built with AWS Lambda, S3, SNS, and CloudWatch. Deployed with a single SAM command.

---

## Architecture

```
AWS Account API Activity
        │
        ▼
  ┌─────────────┐
  │  CloudTrail │  (multi-region, all services, log file validation)
  └──────┬──────┘
         │ delivers logs (.json.gz)
         ▼
  ┌─────────────┐
  │  S3 Bucket  │  (90-day lifecycle)
  └──────┬──────┘
         │ S3 ObjectCreated trigger
         ▼
  ┌──────────────────────────┐
  │     Lambda Function      │  Python 3.12
  │                          │
  │  CT-001  Root usage      │
  │  CT-002  No-MFA login    │
  │  CT-003  IAM mutations   │
  │  CT-004  Trail tampering │
  │  CT-005  Wrong region    │
  └──────┬───────────────────┘
         │
         ├─────────────────────────────┐
         ▼                             ▼
  ┌─────────────┐             ┌──────────────────┐
  │     SNS     │             │   CloudWatch      │
  │  Email Alert│             │  Structured JSON  │
  │  (per rule) │             │  Logs + Dashboard │
  └─────────────┘             └──────────────────┘
```

---

## Detection Rules

| Rule ID | Title | Severity | MITRE ATT&CK |
|---------|-------|----------|--------------|
| CT-001 | Root Account Activity | HIGH | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| CT-002 | Console Login Without MFA | HIGH | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Cloud Accounts |
| CT-003 | Sensitive IAM Action | MEDIUM | [T1136](https://attack.mitre.org/techniques/T1136/) / [T1098](https://attack.mitre.org/techniques/T1098/) / [T1484](https://attack.mitre.org/techniques/T1484/) |
| CT-004 | CloudTrail Tampering | CRITICAL | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses |
| CT-005 | Activity in Unexpected Region | MEDIUM | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Cloud Accounts |

---

## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html) installed
- AWS CLI configured (`aws configure`)
- IAM permissions to create Lambda, S3, CloudTrail, SNS, CloudWatch, and IAM roles

Verify your setup:
```bash
aws sts get-caller-identity
sam --version
```

---

## Deploy

### 1. Clone the repo

```bash
git clone https://github.com/mikelobocyber/cloudtrail-anomaly-alerter
cd cloudtrail-anomaly-alerter
```

### 2. Build

```bash
sam build
```

### 3. Deploy (first time — guided)

```bash
sam deploy --guided \
  --parameter-overrides \
    AlertEmail=your@email.com \
    ExpectedRegions=us-east-1,us-west-2
```

SAM will prompt you to confirm the stack name, region, and S3 bucket for artifacts. Accept the defaults or customize as needed.

### 4. Confirm your SNS subscription

After deploy, AWS sends a confirmation email to the address you provided. **Click "Confirm subscription"** — alerts will not be delivered until you do.

### 5. Verify the stack

```bash
aws cloudformation describe-stacks \
  --stack-name cloudtrail-anomaly-alerter \
  --query "Stacks[0].Outputs"
```

You should see outputs for the Lambda ARN, SNS topic ARN, S3 bucket name, and CloudWatch dashboard URL.

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `AlertEmail` | required | Email address for SNS alert delivery |
| `ExpectedRegions` | `us-east-1,us-west-2` | Comma-separated list of AWS regions where activity is expected |

To update parameters after initial deploy:
```bash
sam deploy \
  --parameter-overrides \
    AlertEmail=new@email.com \
    ExpectedRegions=us-east-1,us-west-2,eu-west-1
```

---

## Testing the Alerter

### Trigger a real finding (safe)

Log into the AWS Console **without MFA** enabled on your test user — this fires CT-002 within a few minutes once CloudTrail delivers the log.

Alternatively, simulate root activity in a test account, or call a sensitive IAM action:
```bash
aws iam create-user --user-name test-anomaly-user
aws iam delete-user --user-name test-anomaly-user
```

This fires CT-003 twice (CreateUser + DeleteUser).

### Run unit tests locally

```bash
pip install pytest
pytest tests/ -v
```

Expected output:
```
tests/test_detectors.py::TestRootUsage::test_detects_root_activity PASSED
tests/test_detectors.py::TestRootUsage::test_mitre_technique_correct PASSED
...
28 passed in 0.12s
```

---

## Alert Format

### SNS Email

```
Subject: [HIGH] CT-002: Console Login Without MFA [T1078.004]

🟠 [HIGH] Console Login Without MFA
Rule: CT-002

Successful AWS Console login by arn:aws:iam::123456789012:user/jsmith
from 203.0.113.5 without MFA.

--- MITRE ATT&CK ---
Technique: T1078.004 — Valid Accounts: Cloud Accounts
Tactic:    Initial Access / Persistence / Defense Evasion / Privilege Escalation
Reference: https://attack.mitre.org/techniques/T1078/004/

--- EVENT DETAILS ---
Time:       2024-03-15T09:00:00Z
Action:     ConsoleLogin
Region:     us-east-1
Actor:      arn:aws:iam::123456789012:user/jsmith
Source IP:  203.0.113.5
Request ID: login-req-001

Generated: 2024-03-15T09:00:05.123456+00:00
```

### CloudWatch Log (structured JSON — SIEM ready)

```json
{
  "level": "FINDING",
  "rule_id": "CT-002",
  "severity": "HIGH",
  "title": "Console Login Without MFA",
  "mitre_technique": "T1078.004",
  "finding": {
    "schema_version": "1.0",
    "rule_id": "CT-002",
    "title": "Console Login Without MFA",
    "description": "Successful AWS Console login by arn:aws:iam::123456789012:user/jsmith from 203.0.113.5 without MFA.",
    "severity": "HIGH",
    "mitre_attack": {
      "technique_id": "T1078.004",
      "technique_name": "Valid Accounts: Cloud Accounts",
      "tactic": "Initial Access / Persistence / Defense Evasion / Privilege Escalation",
      "url": "https://attack.mitre.org/techniques/T1078/004/"
    },
    "event": {
      "event_time": "2024-03-15T09:00:00Z",
      "event_name": "ConsoleLogin",
      "event_source": "signin.amazonaws.com",
      "aws_region": "us-east-1",
      "source_ip": "203.0.113.5",
      "user_agent": "Mozilla/5.0",
      "request_id": "login-req-001",
      "actor_arn": "arn:aws:iam::123456789012:user/jsmith",
      "actor_type": "IAMUser"
    },
    "generated_at": "2024-03-15T09:00:05.123456+00:00"
  }
}
```

---

## Monitoring

After deploy, a CloudWatch dashboard is created at the URL shown in stack outputs.

### Query findings in CloudWatch Logs Insights

```
SOURCE '/aws/lambda/cloudtrail-anomaly-alerter'
| filter level = "FINDING"
| fields rule_id, severity, title, mitre_technique, finding.event.actor_arn, finding.event.source_ip
| sort @timestamp desc
| limit 50
```

Filter by severity:
```
SOURCE '/aws/lambda/cloudtrail-anomaly-alerter'
| filter level = "FINDING" and severity = "CRITICAL"
| sort @timestamp desc
```

---

## Wazuh / SIEM Integration

The Lambda logs every finding as structured JSON to CloudWatch Logs. To forward these to Wazuh or another SIEM:

1. Deploy the [CloudWatch Logs to Wazuh](https://documentation.wazuh.com/current/cloud-security/aws/cloudwatch-logs.html) integration
2. Point it at the log group `/aws/lambda/cloudtrail-anomaly-alerter`
3. Filter on `level = "FINDING"` to isolate alerts

The JSON schema is stable across all rule versions and maps directly to Wazuh alert fields.

---

## Adding Custom Detection Rules

Each detector is a standalone function that receives a CloudTrail event dict and returns a finding dict or `None`.

```python
# lambda/handler.py

def check_s3_public_acl(event: dict) -> dict | None:
    if event.get("eventSource") != "s3.amazonaws.com":
        return None
    if event.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return None
    # Check if ACL grants public access
    params = event.get("requestParameters", {}) or {}
    if "public" not in str(params).lower():
        return None
    return _build_finding(
        rule_id="CT-006",
        title="S3 Public ACL Applied",
        description=f"Public ACL set on S3 resource by {event.get('userIdentity', {}).get('arn')}.",
        severity="HIGH",
        technique_id="T1530",   # Data from Cloud Storage
        event=event,
    )

# Register it
DETECTORS = [..., check_s3_public_acl]
```

Add a corresponding fixture and test in `tests/` to validate it.

---

## Tear Down

```bash
sam delete
```

> Note: The S3 bucket must be empty before SAM can delete it. Empty it first:
> ```bash
> aws s3 rm s3://cloudtrail-anomaly-alerter-<account-id>-<region> --recursive
> ```

---

## Tech Stack

- **AWS Lambda** — Python 3.12, event-driven execution
- **AWS CloudTrail** — multi-region API logging with log file validation
- **Amazon S3** — log storage with 90-day lifecycle
- **Amazon SNS** — email alerting with severity-labeled subjects
- **Amazon CloudWatch** — structured JSON logs and monitoring dashboard
- **AWS SAM** — infrastructure as code, single-command deploy

---

## Related Projects

- [lobo-homelab](https://github.com/mikelobocyber/lobo-homelab) — self-hosted homelab: Proxmox, Wazuh SIEM, Nextcloud
- [cybersecurity-certifications](https://github.com/mikelobocyber/cybersecurity-certifications) — cert roadmap and study notes (Security+, CySA+, OSCP)

---

## License

MIT
