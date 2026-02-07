# netkit.py - Python Edition

Portable Python version of netkit with feature parity to the Rust version.

## Why Python Version?

- **Portability**: Single file, easy to copy to isolated environments
- **No compilation**: Works anywhere Python 3.6+ is installed
- **Easy audit**: ~600 lines of readable Python code
- **Perfect for**: ADC/isolated AWS partitions, hardened environments

## Features

All the same features as the Rust version:

- ✅ **compliance** - Security group compliance checking
- ✅ **vpc-map** - VPC topology visualization with route tables
- ✅ **diff** - Compare two VPCs side-by-side
- ✅ **cost** - Estimate monthly AWS costs
- ✅ **sec-groups** - Detailed security group analysis
- ✅ **subnet** - Subnet calculator
- ✅ **list-vpcs** - List all VPCs

## Requirements

- Python 3.6+
- boto3 (usually pre-installed on AWS boxes)

## Quick Start

```bash
# Export AWS credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Run commands
python3 netkit.py compliance --region us-east-1
python3 netkit.py vpc-map --region us-east-1
python3 netkit.py subnet 10.0.0.0/16 --count 4
```

## Usage Examples

### Security Compliance
```bash
# Check compliance
python3 netkit.py compliance --region us-east-1

# Specific VPC
python3 netkit.py compliance --region us-east-1 --vpc vpc-12345678

# JSON output for CI/CD
python3 netkit.py compliance --json --strict
```

### VPC Topology
```bash
# Map all VPCs
python3 netkit.py vpc-map --region us-east-1

# Map specific VPC
python3 netkit.py vpc-map --vpc vpc-12345678
```

### Compare VPCs
```bash
python3 netkit.py diff vpc-12345678 vpc-87654321 --region us-east-1
```

### Cost Estimation
```bash
python3 netkit.py cost --region us-east-1
```

### Security Groups
```bash
python3 netkit.py sec-groups --region us-east-1 --vpc vpc-12345678
```

### Subnet Calculator
```bash
python3 netkit.py subnet 10.0.0.0/16 --count 6
```

## Deployment to Isolated Environments

### Option 1: SCP
```bash
scp netkit.py user@isolated-box:~/
```

### Option 2: Copy-Paste
Just copy the file content through your jump box terminal.

### Option 3: Git Clone (if allowed)
```bash
git clone https://github.com/YOUR_USERNAME/RustNet.git
cd RustNet
python3 netkit.py --help
```

## Supported AWS Partitions

Works in all AWS partitions:
- Commercial: `us-east-1`, `us-west-2`, etc.
- GovCloud: `us-gov-west-1`, `us-gov-east-1`
- Secret: `us-iso-east-1`, `us-iso-west-1`
- Top Secret: `us-isob-east-1`

## Comparison: Python vs Rust

| Feature | Python | Rust |
|---------|--------|------|
| All commands | ✅ | ✅ |
| Single file | ✅ | ❌ |
| No compilation | ✅ | ❌ |
| Performance | Slower | Faster |
| Dependencies | boto3 | None |
| Best for | Isolated envs | Local dev |
| Local network tools | ❌ | ✅ |

## Exit Codes (CI/CD)

When using `--strict`:
- `0` - No issues
- `1` - HIGH severity issues
- `2` - CRITICAL issues

## License

MIT
