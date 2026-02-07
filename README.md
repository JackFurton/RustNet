# netkit 🦀🔧

A modular network analysis toolkit built in Rust for local network discovery and AWS infrastructure mapping.

## Features

### Local Network Tools
- **`netkit ping <host>`** - Colorized ping output
- **`netkit interfaces`** - Display network interfaces
- **`netkit routes`** - Show routing table
- **`netkit scan <ip> --port <port>`** - TCP port scanner
- **`netkit discover`** - Discover active hosts on local network

### AWS Infrastructure Tools
- **`netkit aws-map`** - Map VPC topology with subnets, instances, and route tables
- **`netkit aws-map --dot`** - Export topology to Graphviz DOT format
- **`netkit sec-groups`** - Analyze security group rules
- **`netkit diff <vpc1> <vpc2>`** - Compare two VPCs side-by-side

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/netkit.git
cd netkit

# Build release binary
cargo build --release

# Binary will be at target/release/netkit
./target/release/netkit --help
```

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
