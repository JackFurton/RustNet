# netkit 🦀🔧

A modular network analysis toolkit built in Rust for local network discovery and AWS infrastructure mapping.

**Available in two flavors:**
- **Rust** - Fast compiled binary with local network tools
- **Python** - Portable single-file version for isolated environments

## Features

### Local Network Tools (Rust only)
- **`netkit ping <host>`** - Colorized ping output
- **`netkit interfaces`** - Display network interfaces
- **`netkit routes`** - Show routing table
- **`netkit scan <ip> --port <port>`** - TCP port scanner
- **`netkit discover`** - Discover active hosts on local network

### AWS Infrastructure Tools (Both versions)
- **`netkit aws-map`** - Map VPC topology with subnets, instances, and route tables
- **`netkit aws-map --dot`** - Export topology to Graphviz DOT format (Rust only)
- **`netkit sec-groups`** - Analyze security group rules
- **`netkit compliance`** - Check security group compliance
  - **`--all-regions`** - Scan all AWS regions (Rust only)
  - **`--strict`** - Exit with error code if issues found (for CI/CD)
  - **`--json`** - Output as JSON
- **`netkit diff <vpc1> <vpc2>`** - Compare two VPCs side-by-side
- **`netkit cost`** - Estimate monthly AWS costs (NAT Gateway, Transit Gateway)
- **`netkit subnet <cidr> --count <n>`** - Calculate subnet splits

## Installation

### Rust Version (Recommended for local use)

```bash
# Clone the repo
git clone https://github.com/JackFurton/RustNet.git
cd RustNet

# Build release binary
cargo build --release

# Binary will be at target/release/netkit
./target/release/netkit --help
```

### Python Version (For isolated/hardened environments)

```bash
# Just copy the single file
cp netkit.py ~/
python3 netkit.py --help

# Or use directly from repo
python3 netkit/netkit.py --help
```

See [PYTHON.md](PYTHON.md) for Python-specific documentation.

## Usage Examples

### Local Network Discovery
```bash
# Scan local subnet for active hosts
netkit discover --network 192.168.1.0/24

# Scan specific port
netkit scan 192.168.1.1 --port 22
```

### AWS VPC Analysis
```bash
# Map VPC topology
netkit aws-map --region us-east-1

# Export to Graphviz
netkit aws-map --dot
# Then paste output into https://dreampuf.github.io/GraphvizOnline/

# Analyze security groups
netkit sec-groups --vpc vpc-12345678

# Compare two VPCs
netkit diff vpc-12345678 vpc-87654321

# Estimate monthly costs
netkit cost --region us-east-1

# CI/CD integration - exit with error if issues found
netkit compliance --strict --json | jq '.total_issues'
```

## Requirements

- Rust 1.70+ (tested on 1.93.0)
- AWS CLI configured with credentials (for AWS commands)
- Linux/macOS (uses `ip` command for network operations)

## Architecture

```
netkit/
├── src/
│   ├── main.rs    # CLI interface and command routing
│   └── aws.rs     # AWS-specific functionality
├── Cargo.toml     # Dependencies
└── README.md
```

## Dependencies

- `clap` - CLI argument parsing
- `colored` - Terminal colors
- `serde_json` - JSON parsing for AWS API responses
- `anyhow` - Error handling

## Roadmap

- [ ] Multi-region comparison
- [ ] Security compliance checker
- [ ] Cost estimation
- [ ] Export to Terraform
- [ ] Real-time monitoring dashboard (TUI)
- [ ] Bandwidth testing

## License

MIT

## Author

Built as a learning project to explore Rust systems programming and AWS infrastructure automation.
