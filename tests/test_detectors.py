"""
Unit tests for CloudTrail Anomaly Alerter detection rules.
Run: pytest tests/ -v
"""

import os
import sys

# Allow import of handler without AWS credentials
os.environ.setdefault("SNS_TOPIC_ARN", "")
os.environ.setdefault("EXPECTED_REGIONS", "us-east-1,us-west-2")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

from handler import (
    analyze_event,
    check_root_usage,
    check_console_login_no_mfa,
    check_sensitive_iam,
    check_cloudtrail_tampering,
    check_unexpected_region,
)
from fixtures import (
    ROOT_USAGE,
    CONSOLE_LOGIN_NO_MFA,
    CONSOLE_LOGIN_WITH_MFA,
    CONSOLE_LOGIN_FAILED,
    IAM_CREATE_USER,
    IAM_ATTACH_ROLE_POLICY,
    IAM_BENIGN_ACTION,
    CLOUDTRAIL_STOP_LOGGING,
    UNEXPECTED_REGION,
    EXPECTED_REGION,
)


# ---------------------------------------------------------------------------
# CT-001: Root usage
# ---------------------------------------------------------------------------

class TestRootUsage:
    def test_detects_root_activity(self):
        finding = check_root_usage(ROOT_USAGE)
        assert finding is not None
        assert finding["rule_id"] == "CT-001"
        assert finding["severity"] == "HIGH"

    def test_mitre_technique_correct(self):
        finding = check_root_usage(ROOT_USAGE)
        assert finding["mitre_attack"]["technique_id"] == "T1078"
        assert finding["mitre_attack"]["url"] == "https://attack.mitre.org/techniques/T1078/"

    def test_no_finding_for_iam_user(self):
        assert check_root_usage(CONSOLE_LOGIN_NO_MFA) is None

    def test_finding_contains_event_details(self):
        finding = check_root_usage(ROOT_USAGE)
        assert finding["event"]["actor_arn"] == ROOT_USAGE["userIdentity"]["arn"]
        assert finding["event"]["aws_region"] == ROOT_USAGE["awsRegion"]


# ---------------------------------------------------------------------------
# CT-002: Console login without MFA
# ---------------------------------------------------------------------------

class TestConsoleLoginNoMFA:
    def test_detects_login_without_mfa(self):
        finding = check_console_login_no_mfa(CONSOLE_LOGIN_NO_MFA)
        assert finding is not None
        assert finding["rule_id"] == "CT-002"
        assert finding["severity"] == "HIGH"

    def test_no_finding_when_mfa_used(self):
        assert check_console_login_no_mfa(CONSOLE_LOGIN_WITH_MFA) is None

    def test_no_finding_on_failed_login(self):
        assert check_console_login_no_mfa(CONSOLE_LOGIN_FAILED) is None

    def test_mitre_technique_correct(self):
        finding = check_console_login_no_mfa(CONSOLE_LOGIN_NO_MFA)
        assert finding["mitre_attack"]["technique_id"] == "T1078.004"

    def test_no_finding_for_non_login_event(self):
        assert check_console_login_no_mfa(ROOT_USAGE) is None


# ---------------------------------------------------------------------------
# CT-003: Sensitive IAM actions
# ---------------------------------------------------------------------------

class TestSensitiveIAM:
    def test_detects_create_user(self):
        finding = check_sensitive_iam(IAM_CREATE_USER)
        assert finding is not None
        assert finding["rule_id"] == "CT-003"
        assert finding["mitre_attack"]["technique_id"] == "T1136"

    def test_detects_attach_role_policy(self):
        finding = check_sensitive_iam(IAM_ATTACH_ROLE_POLICY)
        assert finding is not None
        assert finding["mitre_attack"]["technique_id"] == "T1484"

    def test_no_finding_for_benign_iam_action(self):
        assert check_sensitive_iam(IAM_BENIGN_ACTION) is None

    def test_no_finding_for_non_iam_source(self):
        assert check_sensitive_iam(ROOT_USAGE) is None

    def test_severity_is_medium(self):
        finding = check_sensitive_iam(IAM_CREATE_USER)
        assert finding["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# CT-004: CloudTrail tampering
# ---------------------------------------------------------------------------

class TestCloudTrailTampering:
    def test_detects_stop_logging(self):
        finding = check_cloudtrail_tampering(CLOUDTRAIL_STOP_LOGGING)
        assert finding is not None
        assert finding["rule_id"] == "CT-004"
        assert finding["severity"] == "CRITICAL"

    def test_mitre_technique_correct(self):
        finding = check_cloudtrail_tampering(CLOUDTRAIL_STOP_LOGGING)
        assert finding["mitre_attack"]["technique_id"] == "T1562.001"

    def test_no_finding_for_non_cloudtrail_source(self):
        assert check_cloudtrail_tampering(ROOT_USAGE) is None


# ---------------------------------------------------------------------------
# CT-005: Unexpected region
# ---------------------------------------------------------------------------

class TestUnexpectedRegion:
    def test_detects_unexpected_region(self):
        finding = check_unexpected_region(UNEXPECTED_REGION)
        assert finding is not None
        assert finding["rule_id"] == "CT-005"
        assert "ap-southeast-1" in finding["description"]

    def test_no_finding_for_expected_region(self):
        assert check_unexpected_region(EXPECTED_REGION) is None

    def test_severity_is_medium(self):
        finding = check_unexpected_region(UNEXPECTED_REGION)
        assert finding["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------

class TestFindingSchema:
    def test_required_fields_present(self):
        finding = check_root_usage(ROOT_USAGE)
        for field in ["schema_version", "rule_id", "title", "description",
                      "severity", "mitre_attack", "event", "generated_at"]:
            assert field in finding, f"Missing field: {field}"

    def test_mitre_block_fields_present(self):
        finding = check_root_usage(ROOT_USAGE)
        for field in ["technique_id", "technique_name", "tactic", "url"]:
            assert field in finding["mitre_attack"], f"Missing mitre field: {field}"

    def test_event_block_fields_present(self):
        finding = check_root_usage(ROOT_USAGE)
        for field in ["event_time", "event_name", "event_source",
                      "aws_region", "source_ip", "actor_arn"]:
            assert field in finding["event"], f"Missing event field: {field}"


# ---------------------------------------------------------------------------
# analyze_event (multi-detector)
# ---------------------------------------------------------------------------

class TestAnalyzeEvent:
    def test_returns_list(self):
        assert isinstance(analyze_event(ROOT_USAGE), list)

    def test_benign_event_returns_empty(self):
        benign = {
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/dev"},
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.0.0.1",
            "eventTime": "2024-03-15T10:00:00Z",
            "requestID": "benign-001",
        }
        assert analyze_event(benign) == []

    def test_tamper_event_returns_finding(self):
        findings = analyze_event(CLOUDTRAIL_STOP_LOGGING)
        assert len(findings) >= 1
        rule_ids = [f["rule_id"] for f in findings]
        assert "CT-004" in rule_ids
