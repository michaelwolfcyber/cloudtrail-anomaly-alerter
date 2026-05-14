# CloudTrail Anomaly Alerter — To Do

## GitHub Setup
- [ ] Create repo on GitHub (`cloudtrail-anomaly-alerter`)
- [ ] Add description: `Serverless AWS security tool that detects suspicious CloudTrail activity and maps findings to MITRE ATT&CK — deployed with AWS SAM.`
- [ ] Push all files
- [ ] Add topics/tags on GitHub: `aws`, `security`, `cloudtrail`, `lambda`, `mitre-attack`, `serverless`, `sam`, `siem`, `detection-engineering`

## Deploy & Test
- [ ] Run `pytest tests/ -v` locally — confirm all 28 pass
- [ ] Run `sam build` and `sam deploy --guided`
- [ ] Confirm SNS subscription email
- [ ] Trigger CT-003 via CLI (`aws iam create-user` / `aws iam delete-user`)
- [ ] Verify alert arrives in email
- [ ] Verify finding appears in CloudWatch Logs

## Screenshots to Take
- [ ] SNS email alert (shows rule ID, severity, ATT&CK technique)
- [ ] CloudWatch Logs JSON finding (structured output)
- [ ] CloudWatch dashboard (Lambda invocations + findings query)
- [ ] `pytest` output showing all tests passing

## README Updates
- [ ] Add screenshots folder (`docs/screenshots/`) and embed images in README
- [ ] Add a "Demo" or "Screenshots" section at the top of the README
- [ ] Update Wazuh integration section with real screenshot if you wire it to your homelab

## Tear Down
- [ ] Empty S3 bucket
- [ ] Run `sam delete` when done testing
