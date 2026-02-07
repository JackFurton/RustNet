use anyhow::Result;
use colored::*;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::process::Command;

pub fn map_vpc_topology(region: &str) -> Result<()> {
    println!("{}", "🗺️  Mapping VPC Topology...".cyan().bold());
    println!("{}", "═".repeat(70).bright_black());
    println!("Region: {}", region.yellow());
    println!();
    
    // Check for Transit Gateways first
    let tgws = get_transit_gateways(region)?;
    if !tgws.is_empty() {
        println!("{}", "🌐 Transit Gateways:".yellow().bold());
        for tgw in &tgws {
            let tgw_id = tgw["TransitGatewayId"].as_str().unwrap_or("unknown");
            let state = tgw["State"].as_str().unwrap_or("unknown");
            
            println!("  {} {} - {}", 
                "🔗".cyan(),
                tgw_id.cyan().bold(),
                state.bright_black()
            );
            
            // Get attachments for this TGW
            let attachments = get_tgw_attachments(region, tgw_id)?;
            for att in &attachments {
                let att_id = att["TransitGatewayAttachmentId"].as_str().unwrap_or("unknown");
                let vpc_id = att["ResourceId"].as_str().unwrap_or("unknown");
                let att_state = att["State"].as_str().unwrap_or("unknown");
                
                println!("    ↳ {} → {} ({})", 
                    att_id.bright_black(),
                    vpc_id.green(),
                    att_state.yellow()
                );
            }
        }
        println!();
    }
    
    // Get VPCs
    let vpcs = get_vpcs(region)?;
    
    if vpcs.is_empty() {
        println!("{}", "No VPCs found in this region".yellow());
        return Ok(());
    }
    
    for vpc in vpcs {
        let vpc_id = vpc["VpcId"].as_str().unwrap_or("unknown");
        let cidr = vpc["CidrBlock"].as_str().unwrap_or("unknown");
        let is_default = vpc["IsDefault"].as_bool().unwrap_or(false);
        
        println!("{}", "┌─────────────────────────────────────────────────────────────────┐".bright_black());
        println!("│ {} VPC: {} ({})", 
            if is_default { "🏠" } else { "🏢" },
            vpc_id.cyan().bold(),
            cidr.green()
        );
        
        // Get subnets for this VPC
        let subnets = get_subnets(region, vpc_id)?;
        
        if !subnets.is_empty() {
            println!("│ {}", "Subnets:".yellow());
            for subnet in &subnets {
                let subnet_id = subnet["SubnetId"].as_str().unwrap_or("unknown");
                let subnet_cidr = subnet["CidrBlock"].as_str().unwrap_or("unknown");
                let az = subnet["AvailabilityZone"].as_str().unwrap_or("unknown");
                let available_ips = subnet["AvailableIpAddressCount"].as_u64().unwrap_or(0);
                
                println!("│   • {} ({}) - {} - {} IPs available", 
                    subnet_id.cyan(),
                    subnet_cidr.green(),
                    az.bright_black(),
                    available_ips.to_string().yellow()
                );
            }
            
            // Show route tables
            println!("│ {}", "Route Tables:".yellow());
            let route_tables = get_route_tables(region, vpc_id)?;
            
            // Build a map of subnet -> route table
            let mut subnet_routes: HashMap<String, String> = HashMap::new();
            for rt in &route_tables {
                let rt_id = rt["RouteTableId"].as_str().unwrap_or("unknown").to_string();
                
                // Check associations
                if let Some(assocs) = rt["Associations"].as_array() {
                    for assoc in assocs {
                        if let Some(subnet_id) = assoc["SubnetId"].as_str() {
                            subnet_routes.insert(subnet_id.to_string(), rt_id.clone());
                        }
                    }
                }
            }
            
            // Show routes for each route table
            for rt in &route_tables {
                let rt_id = rt["RouteTableId"].as_str().unwrap_or("unknown");
                
                // Find which subnets use this route table
                let using_subnets: Vec<&String> = subnet_routes.iter()
                    .filter(|(_, v)| v.as_str() == rt_id)
                    .map(|(k, _)| k)
                    .collect();
                
                if !using_subnets.is_empty() {
                    println!("│   📋 {} (used by {} subnet(s))", 
                        rt_id.bright_black(),
                        using_subnets.len().to_string().yellow()
                    );
                    
                    // Show routes
                    if let Some(routes) = rt["Routes"].as_array() {
                        for route in routes {
                            let dest = route["DestinationCidrBlock"].as_str()
                                .or(route["DestinationPrefixListId"].as_str())
                                .unwrap_or("unknown");
                            
                            let target = route["GatewayId"].as_str()
                                .or(route["NatGatewayId"].as_str())
                                .or(route["TransitGatewayId"].as_str())
                                .or(route["NetworkInterfaceId"].as_str())
                                .unwrap_or("local");
                            
                            let state = route["State"].as_str().unwrap_or("active");
                            
                            let icon = if target.starts_with("igw-") {
                                "🌐"  // Internet Gateway
                            } else if target.starts_with("nat-") {
                                "🔀"  // NAT Gateway
                            } else if target.starts_with("tgw-") {
                                "🔗"  // Transit Gateway
                            } else if target == "local" {
                                "🏠"  // Local
                            } else {
                                "→"
                            };
                            
                            println!("│      {} {} → {} ({})", 
                                icon,
                                dest.green(),
                                target.cyan(),
                                state.bright_black()
                            );
                        }
                    }
                }
            }
        }
        
        // Get instances in this VPC
        let instances = get_instances(region, vpc_id)?;
        
        if !instances.is_empty() {
            println!("│ {}", "Instances:".yellow());
            for instance in &instances {
                let instance_id = instance["InstanceId"].as_str().unwrap_or("unknown");
                let state = instance["State"]["Name"].as_str().unwrap_or("unknown");
                let private_ip = instance["PrivateIpAddress"].as_str().unwrap_or("N/A");
                let instance_type = instance["InstanceType"].as_str().unwrap_or("unknown");
                
                let state_icon = match state {
                    "running" => "✅",
                    "stopped" => "⏸️",
                    "terminated" => "❌",
                    _ => "⚠️",
                };
                
                let name = instance["Tags"]
                    .as_array()
                    .and_then(|tags| {
                        tags.iter()
                            .find(|t| t["Key"].as_str() == Some("Name"))
                            .and_then(|t| t["Value"].as_str())
                    })
                    .unwrap_or("unnamed");
                
                println!("│   {} {} ({}) - {} - {} - {}", 
                    state_icon,
                    name.cyan().bold(),
                    instance_id.bright_black(),
                    private_ip.green(),
                    instance_type.yellow(),
                    state.bright_black()
                );
            }
        }
        
        println!("{}", "└─────────────────────────────────────────────────────────────────┘".bright_black());
        println!();
    }
    
    println!("{}", "═".repeat(70).bright_black());
    
    Ok(())
}

fn get_vpcs(region: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&["ec2", "describe-vpcs", "--region", region])
        .output()?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to describe VPCs"));
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    Ok(json["Vpcs"].as_array().unwrap_or(&vec![]).clone())
}

fn get_subnets(region: &str, vpc_id: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&[
            "ec2", "describe-subnets",
            "--region", region,
            "--filters", &format!("Name=vpc-id,Values={}", vpc_id)
        ])
        .output()?;
    
    if !output.status.success() {
        return Ok(vec![]);
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    Ok(json["Subnets"].as_array().unwrap_or(&vec![]).clone())
}

fn get_instances(region: &str, vpc_id: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&[
            "ec2", "describe-instances",
            "--region", region,
            "--filters", &format!("Name=vpc-id,Values={}", vpc_id)
        ])
        .output()?;
    
    if !output.status.success() {
        return Ok(vec![]);
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    
    let mut instances = vec![];
    if let Some(reservations) = json["Reservations"].as_array() {
        for reservation in reservations {
            if let Some(insts) = reservation["Instances"].as_array() {
                instances.extend(insts.clone());
            }
        }
    }
    
    Ok(instances)
}

fn get_transit_gateways(region: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&["ec2", "describe-transit-gateways", "--region", region])
        .output()?;
    
    if !output.status.success() {
        return Ok(vec![]);
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    Ok(json["TransitGateways"].as_array().unwrap_or(&vec![]).clone())
}

fn get_tgw_attachments(region: &str, tgw_id: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&[
            "ec2", "describe-transit-gateway-attachments",
            "--region", region,
            "--filters", &format!("Name=transit-gateway-id,Values={}", tgw_id)
        ])
        .output()?;
    
    if !output.status.success() {
        return Ok(vec![]);
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    Ok(json["TransitGatewayAttachments"].as_array().unwrap_or(&vec![]).clone())
}

fn get_route_tables(region: &str, vpc_id: &str) -> Result<Vec<Value>> {
    let output = Command::new("aws")
        .args(&[
            "ec2", "describe-route-tables",
            "--region", region,
            "--filters", &format!("Name=vpc-id,Values={}", vpc_id)
        ])
        .output()?;
    
    if !output.status.success() {
        return Ok(vec![]);
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    Ok(json["RouteTables"].as_array().unwrap_or(&vec![]).clone())
}

pub fn export_dot(region: &str) -> Result<()> {
    println!("{}", "📊 Exporting to DOT format...".cyan().bold());
    
    let mut dot = String::from("digraph AWS {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box, style=rounded];\n\n");
    
    let vpcs = get_vpcs(region)?;
    
    for vpc in &vpcs {
        let vpc_id = vpc["VpcId"].as_str().unwrap_or("unknown");
        let cidr = vpc["CidrBlock"].as_str().unwrap_or("unknown");
        
        // VPC node
        dot.push_str(&format!("  \"{}\" [label=\"VPC\\n{}\", color=blue, penwidth=2];\n", 
            vpc_id, cidr));
        
        // Subnets
        let subnets = get_subnets(region, vpc_id)?;
        for subnet in &subnets {
            let subnet_id = subnet["SubnetId"].as_str().unwrap_or("unknown");
            let subnet_cidr = subnet["CidrBlock"].as_str().unwrap_or("unknown");
            
            dot.push_str(&format!("  \"{}\" [label=\"Subnet\\n{}\", color=green];\n", 
                subnet_id, subnet_cidr));
            dot.push_str(&format!("  \"{}\" -> \"{}\";\n", vpc_id, subnet_id));
        }
        
        // Instances
        let instances = get_instances(region, vpc_id)?;
        for instance in &instances {
            let instance_id = instance["InstanceId"].as_str().unwrap_or("unknown");
            let private_ip = instance["PrivateIpAddress"].as_str().unwrap_or("N/A");
            let state = instance["State"]["Name"].as_str().unwrap_or("unknown");
            
            let name = instance["Tags"]
                .as_array()
                .and_then(|tags| {
                    tags.iter()
                        .find(|t| t["Key"].as_str() == Some("Name"))
                        .and_then(|t| t["Value"].as_str())
                })
                .unwrap_or("unnamed");
            
            let color = if state == "running" { "green" } else { "red" };
            
            dot.push_str(&format!("  \"{}\" [label=\"{}\\n{}\\n{}\", color={}, shape=ellipse];\n", 
                instance_id, name, instance_id, private_ip, color));
            
            // Connect to subnet
            if let Some(subnet_id) = instance["SubnetId"].as_str() {
                dot.push_str(&format!("  \"{}\" -> \"{}\";\n", subnet_id, instance_id));
            }
        }
        
        // Route tables
        let route_tables = get_route_tables(region, vpc_id)?;
        for rt in &route_tables {
            if let Some(routes) = rt["Routes"].as_array() {
                for route in routes {
                    let dest = route["DestinationCidrBlock"].as_str().unwrap_or("unknown");
                    
                    if let Some(tgw_id) = route["TransitGatewayId"].as_str() {
                        dot.push_str(&format!("  \"{}\" [label=\"TGW\\n{}\", color=purple, shape=diamond];\n", 
                            tgw_id, tgw_id));
                        dot.push_str(&format!("  \"{}\" -> \"{}\" [label=\"{}\"];\n", 
                            vpc_id, tgw_id, dest));
                    } else if let Some(igw_id) = route["GatewayId"].as_str() {
                        if igw_id.starts_with("igw-") {
                            dot.push_str(&format!("  \"{}\" [label=\"IGW\\n{}\", color=orange, shape=diamond];\n", 
                                igw_id, igw_id));
                            dot.push_str(&format!("  \"{}\" -> \"{}\" [label=\"{}\"];\n", 
                                vpc_id, igw_id, dest));
                        }
                    }
                }
            }
        }
        
        dot.push_str("\n");
    }
    
    dot.push_str("}\n");
    
    // Write to file
    let filename = format!("aws-topology-{}.dot", region);
    let mut file = File::create(&filename)?;
    file.write_all(dot.as_bytes())?;
    
    println!("{} Exported to: {}", "✅".green(), filename.cyan().bold());
    println!("View at: {}", "https://dreampuf.github.io/GraphvizOnline/".yellow());
    
    Ok(())
}

pub fn analyze_security_groups(region: &str, vpc_filter: Option<&str>) -> Result<()> {
    println!("{}", "🔒 Analyzing Security Groups...".cyan().bold());
    println!("{}", "═".repeat(70).bright_black());
    println!("Region: {}", region.yellow());
    if let Some(vpc) = vpc_filter {
        println!("VPC Filter: {}", vpc.yellow());
    }
    println!();
    
    let mut args = vec!["ec2", "describe-security-groups", "--region", region];
    let filter_arg;
    if let Some(vpc) = vpc_filter {
        filter_arg = format!("Name=vpc-id,Values={}", vpc);
        args.extend(&["--filters", &filter_arg]);
    }
    
    let output = Command::new("aws").args(&args).output()?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to describe security groups"));
    }
    
    let json: Value = serde_json::from_slice(&output.stdout)?;
    let empty_vec = vec![];
    let sgs = json["SecurityGroups"].as_array().unwrap_or(&empty_vec);
    
    for sg in sgs {
        let sg_id = sg["GroupId"].as_str().unwrap_or("unknown");
        let sg_name = sg["GroupName"].as_str().unwrap_or("unnamed");
        let vpc_id = sg["VpcId"].as_str().unwrap_or("N/A");
        
        println!("{}", "┌─────────────────────────────────────────────────────────────────┐".bright_black());
        println!("│ 🛡️  {} ({})", sg_name.cyan().bold(), sg_id.bright_black());
        println!("│ VPC: {}", vpc_id.green());
        
        // Ingress rules
        if let Some(ingress) = sg["IpPermissions"].as_array() {
            if !ingress.is_empty() {
                println!("│");
                println!("│ {} Inbound Rules:", "⬇️".green());
                
                for rule in ingress {
                    let protocol = rule["IpProtocol"].as_str().unwrap_or("-1");
                    let from_port = rule["FromPort"].as_i64();
                    let to_port = rule["ToPort"].as_i64();
                    
                    let port_str = match (from_port, to_port) {
                        (Some(f), Some(t)) if f == t => format!(":{}", f),
                        (Some(f), Some(t)) => format!(":{}−{}", f, t),
                        _ => String::from(":ALL"),
                    };
                    
                    let proto = if protocol == "-1" { "ALL" } else { protocol };
                    
                    // IP ranges
                    if let Some(ip_ranges) = rule["IpRanges"].as_array() {
                        for ip_range in ip_ranges {
                            let cidr = ip_range["CidrIp"].as_str().unwrap_or("unknown");
                            let desc = ip_range["Description"].as_str().unwrap_or("");
                            
                            println!("│   • {} {} from {} {}", 
                                proto.yellow(),
                                port_str.cyan(),
                                cidr.green(),
                                if !desc.is_empty() { format!("({})", desc) } else { String::new() }.bright_black()
                            );
                        }
                    }
                    
                    // Security group sources
                    if let Some(sg_pairs) = rule["UserIdGroupPairs"].as_array() {
                        for pair in sg_pairs {
                            let source_sg = pair["GroupId"].as_str().unwrap_or("unknown");
                            println!("│   • {} {} from SG {}", 
                                proto.yellow(),
                                port_str.cyan(),
                                source_sg.green()
                            );
                        }
                    }
                }
            }
        }
        
        // Egress rules
        if let Some(egress) = sg["IpPermissionsEgress"].as_array() {
            if !egress.is_empty() {
                println!("│");
                println!("│ {} Outbound Rules:", "⬆️".red());
                
                for rule in egress {
                    let protocol = rule["IpProtocol"].as_str().unwrap_or("-1");
                    let from_port = rule["FromPort"].as_i64();
                    let to_port = rule["ToPort"].as_i64();
                    
                    let port_str = match (from_port, to_port) {
                        (Some(f), Some(t)) if f == t => format!(":{}", f),
                        (Some(f), Some(t)) => format!(":{}−{}", f, t),
                        _ => String::from(":ALL"),
                    };
                    
                    let proto = if protocol == "-1" { "ALL" } else { protocol };
                    
                    if let Some(ip_ranges) = rule["IpRanges"].as_array() {
                        for ip_range in ip_ranges {
                            let cidr = ip_range["CidrIp"].as_str().unwrap_or("unknown");
                            println!("│   • {} {} to {}", 
                                proto.yellow(),
                                port_str.cyan(),
                                cidr.green()
                            );
                        }
                    }
                }
            }
        }
        
        println!("{}", "└─────────────────────────────────────────────────────────────────┘".bright_black());
        println!();
    }
    
    println!("{}", "═".repeat(70).bright_black());
    println!("Total: {} security group(s)", sgs.len().to_string().green().bold());
    
    Ok(())
}

pub fn diff_vpcs(region: &str, vpc1_id: &str, vpc2_id: &str) -> Result<()> {
    println!("{}", "🔍 Comparing VPCs...".cyan().bold());
    println!("{}", "═".repeat(70).bright_black());
    
    // Get VPC info
    let vpcs = get_vpcs(region)?;
    let vpc1 = vpcs.iter().find(|v| v["VpcId"].as_str() == Some(vpc1_id));
    let vpc2 = vpcs.iter().find(|v| v["VpcId"].as_str() == Some(vpc2_id));
    
    if vpc1.is_none() || vpc2.is_none() {
        return Err(anyhow::anyhow!("One or both VPCs not found"));
    }
    
    let vpc1 = vpc1.unwrap();
    let vpc2 = vpc2.unwrap();
    
    println!("VPC 1: {} ({})", 
        vpc1_id.cyan().bold(), 
        vpc1["CidrBlock"].as_str().unwrap_or("unknown").green()
    );
    println!("VPC 2: {} ({})", 
        vpc2_id.cyan().bold(), 
        vpc2["CidrBlock"].as_str().unwrap_or("unknown").green()
    );
    println!();
    
    // Compare subnets
    let subnets1 = get_subnets(region, vpc1_id)?;
    let subnets2 = get_subnets(region, vpc2_id)?;
    
    let cidrs1: HashSet<String> = subnets1.iter()
        .filter_map(|s| s["CidrBlock"].as_str().map(String::from))
        .collect();
    let cidrs2: HashSet<String> = subnets2.iter()
        .filter_map(|s| s["CidrBlock"].as_str().map(String::from))
        .collect();
    
    println!("{}", "📊 Subnets:".yellow().bold());
    println!("  VPC 1: {} subnet(s)", subnets1.len().to_string().cyan());
    println!("  VPC 2: {} subnet(s)", subnets2.len().to_string().cyan());
    
    let only_vpc1: Vec<_> = cidrs1.difference(&cidrs2).collect();
    let only_vpc2: Vec<_> = cidrs2.difference(&cidrs1).collect();
    
    if !only_vpc1.is_empty() {
        println!("  {} Only in VPC 1: {}", "−".red(), only_vpc1.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").red());
    }
    if !only_vpc2.is_empty() {
        println!("  {} Only in VPC 2: {}", "+".green(), only_vpc2.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").green());
    }
    println!();
    
    // Compare instances
    let instances1 = get_instances(region, vpc1_id)?;
    let instances2 = get_instances(region, vpc2_id)?;
    
    let running1 = instances1.iter().filter(|i| i["State"]["Name"].as_str() == Some("running")).count();
    let running2 = instances2.iter().filter(|i| i["State"]["Name"].as_str() == Some("running")).count();
    
    println!("{}", "💻 Instances:".yellow().bold());
    println!("  VPC 1: {} total, {} running", 
        instances1.len().to_string().cyan(),
        running1.to_string().green()
    );
    println!("  VPC 2: {} total, {} running", 
        instances2.len().to_string().cyan(),
        running2.to_string().green()
    );
    
    let types1: HashSet<String> = instances1.iter()
        .filter_map(|i| i["InstanceType"].as_str().map(String::from))
        .collect();
    let types2: HashSet<String> = instances2.iter()
        .filter_map(|i| i["InstanceType"].as_str().map(String::from))
        .collect();
    
    if !types1.is_empty() || !types2.is_empty() {
        println!("  Instance types:");
        println!("    VPC 1: {}", types1.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").bright_black());
        println!("    VPC 2: {}", types2.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").bright_black());
    }
    println!();
    
    // Compare route tables
    let rts1 = get_route_tables(region, vpc1_id)?;
    let rts2 = get_route_tables(region, vpc2_id)?;
    
    println!("{}", "🗺️  Route Tables:".yellow().bold());
    println!("  VPC 1: {} route table(s)", rts1.len().to_string().cyan());
    println!("  VPC 2: {} route table(s)", rts2.len().to_string().cyan());
    
    // Extract unique route destinations
    let mut dests1 = HashSet::new();
    let mut dests2 = HashSet::new();
    
    for rt in &rts1 {
        if let Some(routes) = rt["Routes"].as_array() {
            for route in routes {
                if let Some(dest) = route["DestinationCidrBlock"].as_str() {
                    if dest != "local" {
                        dests1.insert(dest.to_string());
                    }
                }
            }
        }
    }
    
    for rt in &rts2 {
        if let Some(routes) = rt["Routes"].as_array() {
            for route in routes {
                if let Some(dest) = route["DestinationCidrBlock"].as_str() {
                    if dest != "local" {
                        dests2.insert(dest.to_string());
                    }
                }
            }
        }
    }
    
    let only_rt1: Vec<_> = dests1.difference(&dests2).collect();
    let only_rt2: Vec<_> = dests2.difference(&dests1).collect();
    
    if !only_rt1.is_empty() {
        println!("  {} Routes only in VPC 1: {}", "−".red(), only_rt1.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").red());
    }
    if !only_rt2.is_empty() {
        println!("  {} Routes only in VPC 2: {}", "+".green(), only_rt2.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").green());
    }
    
    let common: Vec<_> = dests1.intersection(&dests2).collect();
    if !common.is_empty() {
        println!("  {} Common routes: {}", "=".yellow(), common.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ").bright_black());
    }
    
    println!();
    println!("{}", "═".repeat(70).bright_black());
    
    Ok(())
}
