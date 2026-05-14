# Sample CloudTrail event payloads for unit tests

ROOT_USAGE = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Root",
        "principalId": "123456789012",
        "arn": "arn:aws:iam::123456789012:root",
        "accountId": "123456789012",
    },
    "eventTime": "2024-03-15T02:31:44Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "DescribeInstances",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.42",
    "userAgent": "aws-cli/2.0",
    "requestID": "root-req-001",
}

CONSOLE_LOGIN_NO_MFA = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/jsmith",
        "accountId": "123456789012",
    },
    "eventTime": "2024-03-15T09:00:00Z",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.5",
    "userAgent": "Mozilla/5.0",
    "requestID": "login-req-001",
    "responseElements": {"ConsoleLogin": "Success"},
    "additionalEventData": {"MFAUsed": "No"},
}

CONSOLE_LOGIN_WITH_MFA = {
    **CONSOLE_LOGIN_NO_MFA,
    "additionalEventData": {"MFAUsed": "Yes"},
    "requestID": "login-req-002",
}

CONSOLE_LOGIN_FAILED = {
    **CONSOLE_LOGIN_NO_MFA,
    "responseElements": {"ConsoleLogin": "Failure"},
    "requestID": "login-req-003",
}

IAM_CREATE_USER = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/admin",
        "accountId": "123456789012",
    },
    "eventTime": "2024-03-15T10:00:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateUser",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "10.0.0.1",
    "userAgent": "aws-cli/2.0",
    "requestID": "iam-req-001",
}

IAM_ATTACH_ROLE_POLICY = {
    **IAM_CREATE_USER,
    "eventName": "AttachRolePolicy",
    "requestID": "iam-req-002",
}

IAM_BENIGN_ACTION = {
    **IAM_CREATE_USER,
    "eventName": "ListUsers",
    "requestID": "iam-req-003",
}

CLOUDTRAIL_STOP_LOGGING = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/attacker",
        "accountId": "123456789012",
    },
    "eventTime": "2024-03-15T03:00:00Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.99",
    "userAgent": "aws-cli/2.0",
    "requestID": "ct-req-001",
}

UNEXPECTED_REGION = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/jsmith",
        "accountId": "123456789012",
    },
    "eventTime": "2024-03-15T12:00:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "RunInstances",
    "awsRegion": "ap-southeast-1",
    "sourceIPAddress": "10.0.0.5",
    "userAgent": "aws-cli/2.0",
    "requestID": "region-req-001",
}

EXPECTED_REGION = {
    **UNEXPECTED_REGION,
    "awsRegion": "us-east-1",
    "requestID": "region-req-002",
}
