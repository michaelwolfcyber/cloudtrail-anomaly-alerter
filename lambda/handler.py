import boto3
import gzip
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
EXPECTED_REGIONS = set(
    os.environ.get("EXPECTED_REGIONS", "us-east-1,us-west-2").split(",")
)

# ---------------------------------------------------------------------------
# MITRE ATT&CK reference
# ---------------------------------------------------------------------------

ATTACK_TECHNIQUES = {
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Defense Evasion / Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.004": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access / Persistence / Defense Evasion / Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    "T1136": {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence / Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1562.001": {
        "id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1484": {
        "id": "T1484",
        "name": "Domain or Tenant Policy Modification",
        "tactic": "Defense Evasion / Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1484/",
    },
}

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

SENSITIVE_IAM_ACTIONS = {
    "CreateUser":             "T1136",
    "DeleteUser":             "T1098",
    "AttachUserPolicy":       "T1098",
    "DetachUserPolicy":       "T1098",
    "CreateAccessKey":        "T1098",
    "DeleteAccessKey":        "T1098",
    "PutUserPolicy":          "T1098",
    "DeleteUserPolicy":       "T1098",
    "CreateRole":             "T1136",
    "DeleteRole":             "T1098",
    "AttachRolePolicy":       "T1484",
    "DetachRolePolicy":       "T1484",
    "UpdateAssumeRolePolicy": "T1484",
    "CreatePolicy":           "T1484",
    "DeletePolicy":           "T1484",
    "AddUserToGroup":         "T1098",
    "RemoveUserFromGroup":    "T1098",
}

CLOUDTRAIL_TAMPER_ACTIONS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
}


def _build_finding(rule_id, title, description, severity, technique_id, event):
    technique = ATTACK_TECHNIQUES.get(technique_id, {})
    return {
        "schema_version": "1.0",
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "mitre_attack": {
            "technique_id": technique.get("id", technique_id),
            "technique_name": technique.get("name", ""),
            "tactic": technique.get("tactic", ""),
            "url": technique.get("url", ""),
        },
        "event": {
            "event_time": event.get("eventTime"),
            "event_name": event.get("eventName"),
            "event_source": event.get("eventSource"),
            "aws_region": event.get("awsRegion"),
            "source_ip": event.get("sourceIPAddress"),
            "user_agent": event.get("userAgent"),
            "request_id": event.get("requestID"),
            "actor_arn": event.get("userIdentity", {}).get("arn"),
            "actor_type": event.get("userIdentity", {}).get("type"),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def check_root_usage(event):
    if event.get("userIdentity", {}).get("type") != "Root":
        return None
    return _build_finding(
        rule_id="CT-001",
        title="Root Account Activity Detected",
        description=(
            f"The AWS root account executed '{event.get('eventName')}' "
            f"in {event.get('awsRegion')}. Root usage is strongly discouraged "
            "and may indicate account compromise."
        ),
        severity="HIGH",
        technique_id="T1078",
        event=event,
    )


def check_console_login_no_mfa(event):
    if event.get("eventName") != "ConsoleLogin":
        return None
    response = event.get("responseElements") or {}
    additional = event.get("additionalEventData") or {}
    if response.get("ConsoleLogin") != "Success":
        return None
    if additional.get("MFAUsed") == "Yes":
        return None
    return _build_finding(
        rule_id="CT-002",
        title="Console Login Without MFA",
        description=(
            f"Successful AWS Console login by "
            f"{event.get('userIdentity', {}).get('arn', 'unknown')} "
            f"from {event.get('sourceIPAddress')} without MFA."
        ),
        severity="HIGH",
        technique_id="T1078.004",
        event=event,
    )


def check_sensitive_iam(event):
    if event.get("eventSource") != "iam.amazonaws.com":
        return None
    action = event.get("eventName", "")
    technique_id = SENSITIVE_IAM_ACTIONS.get(action)
    if not technique_id:
        return None
    return _build_finding(
        rule_id="CT-003",
        title=f"Sensitive IAM Action: {action}",
        description=(
            f"'{action}' was called by "
            f"{event.get('userIdentity', {}).get('arn', 'unknown')}. "
            "This action can be used to establish persistence or escalate privileges."
        ),
        severity="MEDIUM",
        technique_id=technique_id,
        event=event,
    )


def check_cloudtrail_tampering(event):
    if event.get("eventSource") != "cloudtrail.amazonaws.com":
        return None
    if event.get("eventName") not in CLOUDTRAIL_TAMPER_ACTIONS:
        return None
    return _build_finding(
        rule_id="CT-004",
        title=f"CloudTrail Tampering: {event.get('eventName')}",
        description=(
            f"'{event.get('eventName')}' was called by "
            f"{event.get('userIdentity', {}).get('arn', 'unknown')}. "
            "This disables or modifies audit logging and is a strong indicator "
            "of an attacker covering their tracks."
        ),
        severity="CRITICAL",
        technique_id="T1562.001",
        event=event,
    )


def check_unexpected_region(event):
    region = event.get("awsRegion", "")
    if not region or region in EXPECTED_REGIONS:
        return None
    return _build_finding(
        rule_id="CT-005",
        title=f"Activity in Unexpected Region: {region}",
        description=(
            f"'{event.get('eventName')}' by "
            f"{event.get('userIdentity', {}).get('arn', 'unknown')} "
            f"occurred in '{region}', outside expected regions "
            f"({', '.join(sorted(EXPECTED_REGIONS))})."
        ),
        severity="MEDIUM",
        technique_id="T1078.004",
        event=event,
    )


DETECTORS = [
    check_root_usage,
    check_console_login_no_mfa,
    check_sensitive_iam,
    check_cloudtrail_tampering,
    check_unexpected_region,
]


def analyze_event(event):
    return [f for detector in DETECTORS for f in [detector(event)] if f]


# ---------------------------------------------------------------------------
# S3 log parsing
# ---------------------------------------------------------------------------

def load_log_file(bucket, key):
    s3 = boto3.client("s3")
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response["Body"].read()
    if key.endswith(".gz"):
        body = gzip.decompress(body)
    return json.loads(body).get("Records", [])


# ---------------------------------------------------------------------------
# Alert dispatch
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def format_sns_message(finding):
    sev = finding["severity"]
    attack = finding["mitre_attack"]
    ev = finding["event"]
    emoji = SEVERITY_EMOJI.get(sev, "")
    return (
        f"{emoji} [{sev}] {finding['title']}\n"
        f"Rule: {finding['rule_id']}\n\n"
        f"{finding['description']}\n\n"
        f"--- MITRE ATT&CK ---\n"
        f"Technique: {attack['technique_id']} — {attack['technique_name']}\n"
        f"Tactic:    {attack['tactic']}\n"
        f"Reference: {attack['url']}\n\n"
        f"--- EVENT DETAILS ---\n"
        f"Time:       {ev['event_time']}\n"
        f"Action:     {ev['event_name']}\n"
        f"Region:     {ev['aws_region']}\n"
        f"Actor:      {ev['actor_arn']}\n"
        f"Source IP:  {ev['source_ip']}\n"
        f"Request ID: {ev['request_id']}\n\n"
        f"Generated: {finding['generated_at']}"
    )


def publish_finding(finding):
    sev = finding["severity"]
    title = finding["title"]
    rule_id = finding["rule_id"]
    attack_id = finding["mitre_attack"]["technique_id"]

    # Structured JSON log — SIEM / Wazuh ingest ready
    logger.warning(json.dumps({
        "level": "FINDING",
        "rule_id": rule_id,
        "severity": sev,
        "title": title,
        "mitre_technique": attack_id,
        "finding": finding,
    }))

    if SNS_TOPIC_ARN:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{sev}] {rule_id}: {title} [{attack_id}]",
            Message=format_sns_message(finding),
        )


# ---------------------------------------------------------------------------
# Lambda entrypoint
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    logger.info(json.dumps({"level": "INFO", "message": "Invoked", "s3_event": event}))

    total_events = 0
    total_findings = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        logger.info(json.dumps({"level": "INFO", "message": f"Processing s3://{bucket}/{key}"}))

        try:
            cloudtrail_records = load_log_file(bucket, key)
        except Exception as e:
            logger.error(json.dumps({"level": "ERROR", "message": str(e)}))
            continue

        for ct_event in cloudtrail_records:
            total_events += 1
            for finding in analyze_event(ct_event):
                total_findings += 1
                publish_finding(finding)

    summary = {"events_scanned": total_events, "findings_generated": total_findings}
    logger.info(json.dumps({"level": "INFO", "message": "Complete", **summary}))
    return summary
