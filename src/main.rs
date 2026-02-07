use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::process::Command;

mod aws;

#[derive(Parser)]
#[command(name = "netkit")]
#[command(about = "AWS Network Analysis Toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ping test between hosts
    Ping {
        /// Target IP or hostname
        target: String,
        
        /// Number of packets
        #[arg(short, long, default_value = "4")]
        count: u32,
    },
    
    /// Show network interfaces
    Interfaces,
    
    /// Show routing table
    Routes,
    
    /// TCP port scan
    Scan {
        /// Target IP
        target: String,
        
        /// Port to scan
        #[arg(short, long)]
        port: u16,
    },
    
    /// Discover hosts on local network
    Discover {
        /// Network to scan (e.g., 172.31.64.0/24)
        #[arg(short, long)]
        network: Option<String>,
    },
    
    /// Map AWS VPC topology
    AwsMap {
        /// AWS Region
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
        
        /// Export to DOT format (Graphviz)
        #[arg(long)]
        dot: bool,
    },
    
    /// Analyze security groups
    SecGroups {
        /// AWS Region
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
        
        /// VPC ID to filter
        #[arg(short, long)]
        vpc: Option<String>,
    },
    
    /// Compare two VPCs
    Diff {
        /// First VPC ID
        vpc1: String,
        
        /// Second VPC ID
        vpc2: String,
        
        /// AWS Region
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Ping { target, count } => {
            println!("{}", format!("🏓 Pinging {}...", target).cyan().bold());
            println!();
            
            let output = Command::new("ping")
                .arg("-c")
                .arg(count.to_string())
                .arg(&target)
                .output()?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // Parse and colorize output
            for line in stdout.lines() {
                if line.contains("bytes from") {
                    println!("{}", line.green());
                } else if line.contains("packet loss") {
                    if line.contains("0% packet loss") {
                        println!("{}", line.green().bold());
                    } else {
                        println!("{}", line.yellow().bold());
                    }
                } else if line.contains("rtt") {
                    println!("{}", line.cyan());
                } else {
                    println!("{}", line);
                }
            }
        }
        
        Commands::Interfaces => {
            println!("{}", "🌐 Network Interfaces".cyan().bold());
            println!("{}", "═".repeat(60).bright_black());
            
            let output = Command::new("ip")
                .arg("addr")
                .arg("show")
                .output()?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                if line.contains(": <") {
                    println!("{}", line.yellow().bold());
                } else if line.contains("inet ") {
                    println!("{}", line.green());
                } else if line.contains("link/") {
                    println!("{}", line.cyan());
                } else {
                    println!("{}", line.bright_black());
                }
            }
        }
        
        Commands::Routes => {
            println!("{}", "🗺️  Routing Table".cyan().bold());
            println!("{}", "═".repeat(60).bright_black());
            
            let output = Command::new("ip")
                .arg("route")
                .arg("show")
                .output()?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                if line.contains("default") {
                    println!("{}", line.yellow().bold());
                } else if line.contains("proto kernel") {
                    println!("{}", line.green());
                } else {
                    println!("{}", line.cyan());
                }
            }
        }
        
        Commands::Scan { target, port } => {
            println!("{}", format!("🔍 Scanning {}:{}...", target, port).cyan().bold());
            
            use std::net::{TcpStream, ToSocketAddrs};
            use std::time::Duration;
            
            let addr = format!("{}:{}", target, port);
            let socket_addr = addr.to_socket_addrs()?.next()
                .ok_or_else(|| anyhow::anyhow!("Invalid address"))?;
            
            match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3)) {
                Ok(_) => {
                    println!("{} Port {} is {}", "✅".green(), port, "OPEN".green().bold());
                }
                Err(_) => {
                    println!("{} Port {} is {}", "❌".red(), port, "CLOSED".red().bold());
                }
            }
        }
        
        Commands::Discover { network } => {
            println!("{}", "🔍 Discovering network hosts...".cyan().bold());
            println!("{}", "═".repeat(60).bright_black());
            
            // Get local network if not specified
            let net = if let Some(n) = network {
                n
            } else {
                // Auto-detect from ip addr
                let output = Command::new("ip")
                    .arg("addr")
                    .arg("show")
                    .output()?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut local_net = String::new();
                
                for line in stdout.lines() {
                    if line.contains("inet ") && !line.contains("127.0.0.1") {
                        if let Some(ip_part) = line.split_whitespace().nth(1) {
                            local_net = ip_part.to_string();
                            break;
                        }
                    }
                }
                
                if local_net.is_empty() {
                    return Err(anyhow::anyhow!("Could not detect local network"));
                }
                
                local_net
            };
            
            println!("Network: {}", net.yellow());
            println!();
            
            // Parse CIDR
            let parts: Vec<&str> = net.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid CIDR format"));
            }
            
            let base_ip = parts[0];
            let ip_parts: Vec<&str> = base_ip.split('.').collect();
            if ip_parts.len() != 4 {
                return Err(anyhow::anyhow!("Invalid IP format"));
            }
            
            let base = format!("{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2]);
            
            println!("{}", "Scanning hosts (this may take a moment)...".bright_black());
            println!();
            
            use std::net::TcpStream;
            use std::time::Duration;
            
            let mut found = 0;
            
            // Quick scan - just check if host responds on common ports
            for i in 1..255 {
                let ip = format!("{}.{}", base, i);
                
                // Try SSH port (22) as a quick check
                let addr = format!("{}:22", ip);
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                    if TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100)).is_ok() {
                        println!("{} {} {}", "✅".green(), ip.cyan(), "(SSH open)".bright_black());
                        found += 1;
                    }
                }
            }
            
            println!();
            println!("{}", "═".repeat(60).bright_black());
            println!("Found {} active host(s)", found.to_string().green().bold());
            println!("{}", "═".repeat(60).bright_black());
        }
        
        Commands::AwsMap { region, dot } => {
            if dot {
                aws::export_dot(&region)?;
            } else {
                aws::map_vpc_topology(&region)?;
            }
        }
        
        Commands::SecGroups { region, vpc } => {
            aws::analyze_security_groups(&region, vpc.as_deref())?;
        }
        
        Commands::Diff { vpc1, vpc2, region } => {
            aws::diff_vpcs(&region, &vpc1, &vpc2)?;
        }
    }
    
    Ok(())
}
