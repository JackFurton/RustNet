# CI/CD Integration

## GitHub Actions

See `.github/workflows/compliance.yml` for a complete example.

### Quick Setup

1. Add AWS credentials to GitHub Secrets:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`

2. The workflow will:
   - Build netkit
   - Run compliance checks
   - Fail the build if HIGH or CRITICAL issues found
   - Upload JSON reports as artifacts

### Exit Codes

```bash
netkit compliance --strict
```

Returns:
- `0` - No issues or only MEDIUM severity
- `1` - HIGH severity issues found
- `2` - CRITICAL issues found

### JSON Output for Parsing

```bash
netkit compliance --json | jq '.total_issues'
netkit compliance --json | jq '.issues[] | select(.severity == "CRITICAL")'
```

## GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - cargo build --release
    - ./target/release/netkit compliance --strict --json > report.json
    - cat report.json | jq '.'
  artifacts:
    reports:
      junit: report.json
    when: always
  allow_failure: false
```

## Jenkins

```groovy
stage('Security Compliance') {
    steps {
        sh 'cargo build --release'
        sh './target/release/netkit compliance --strict --json > compliance.json'
        
        script {
            def report = readJSON file: 'compliance.json'
            if (report.critical > 0) {
                error("Critical security issues found: ${report.critical}")
            } else if (report.high > 0) {
                unstable("High severity issues found: ${report.high}")
            }
        }
    }
}
```

## AWS CodePipeline

```yaml
version: 0.2

phases:
  install:
    commands:
      - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      - source $HOME/.cargo/env
  
  build:
    commands:
      - cargo build --release
  
  post_build:
    commands:
      - ./target/release/netkit compliance --all-regions --strict --json > compliance.json
      - aws s3 cp compliance.json s3://my-compliance-reports/$(date +%Y-%m-%d).json

artifacts:
  files:
    - compliance.json
```

## Slack Notifications

```bash
#!/bin/bash
REPORT=$(./target/release/netkit compliance --json)
CRITICAL=$(echo $REPORT | jq '.critical')
HIGH=$(echo $REPORT | jq '.high')

if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠️ Security issues found: $CRITICAL critical, $HIGH high\"}" \
    $SLACK_WEBHOOK_URL
fi
```

## Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-push

echo "Running security compliance check..."
./target/release/netkit compliance --strict

if [ $? -ne 0 ]; then
  echo "❌ Security issues found. Fix before pushing!"
  exit 1
fi

echo "✅ Security check passed"
```
