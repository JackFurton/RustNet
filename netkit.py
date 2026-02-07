#!/usr/bin/env python3
"""
netkit.py - Network Analysis Toolkit (Python Edition)

Full-featured network toolkit matching the Rust version.
Designed for portability to isolated/hardened environments.

Usage:
    python3 netkit.py <command> [options]

Commands:
    compliance      Check security group compliance
    vpc-map         Map VPC topology
    diff            Compare two VPCs
    cost            Estimate monthly costs
    sec-groups      Analyze security groups
    subnet          Calculate subnet splits
    list-vpcs       List all VPCs

Requirements: boto3
"""

import argparse
import json
import sys
import ipaddress
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 not found. Install with: pip3 install boto3")
    sys.exit(1)


class Colors:
    """ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.YELLOW = ''
        Colors.BLUE = Colors.CYAN = Colors.BOLD = Colors.END = ''


def get_session(region):
    """Create boto3 session"""
    try:
        session = boto3.Session(region_name=region)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        return session, identity
    except NoCredentialsError:
        print(f"{Colors.RED}ERROR: No AWS credentials found{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.END}")
        sys.exit(1)


def check_compliance(args):
    """Security compliance checker"""
    if args.json:
        Colors.disable()
    
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    if not args.json:
        print(f"{Colors.CYAN}{Colors.BOLD}Security Compliance Check{Colors.END}")
        print("=" * 70)
        print(f"Region: {Colors.YELLOW}{args.region}{Colors.END}")
        print(f"Account: {Colors.YELLOW}{identity['Account']}{Colors.END}")
        if args.vpc:
            print(f"VPC: {Colors.YELLOW}{args.vpc}{Colors.END}")
        print()
    
    filters = [{'Name': 'vpc-id', 'Values': [args.vpc]}] if args.vpc else []
    
    try:
        response = ec2.describe_security_groups(Filters=filters)
    except ClientError as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.END}")
        return 1
    
    risky_ports = {
        22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
        1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch',
    }
    
    issues = []
    
    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        
        for rule in sg.get('IpPermissions', []):
            protocol = rule.get('IpProtocol', '-1')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                
                if cidr == '0.0.0.0/0':
                    if protocol == '-1':
                        issues.append({
                            'severity': 'CRITICAL',
                            'sg_id': sg_id,
                            'sg_name': sg_name,
                            'protocol': 'ALL',
                            'port': 'ALL',
                            'source': cidr,
                            'description': 'All traffic allowed from internet'
                        })
                    else:
                        for port, service in risky_ports.items():
                            if from_port and to_port and from_port <= port <= to_port:
                                issues.append({
                                    'severity': 'HIGH',
                                    'sg_id': sg_id,
                                    'sg_name': sg_name,
                                    'protocol': protocol,
                                    'port': f'{port} ({service})',
                                    'source': cidr,
                                    'description': f'{service} exposed to internet'
                                })
                
                elif cidr.endswith('/8') or cidr.endswith('/16'):
                    if from_port and to_port:
                        for port, service in risky_ports.items():
                            if from_port <= port <= to_port:
                                issues.append({
                                    'severity': 'MEDIUM',
                                    'sg_id': sg_id,
                                    'sg_name': sg_name,
                                    'protocol': protocol,
                                    'port': f'{port} ({service})',
                                    'source': cidr,
                                    'description': f'{service} exposed to large CIDR block'
                                })
    
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    issues.sort(key=lambda x: severity_order.get(x['severity'], 3))
    
    critical = sum(1 for i in issues if i['severity'] == 'CRITICAL')
    high = sum(1 for i in issues if i['severity'] == 'HIGH')
    medium = sum(1 for i in issues if i['severity'] == 'MEDIUM')
    
    if args.json:
        output = {
            'region': args.region,
            'account': identity['Account'],
            'vpc_id': args.vpc,
            'total_issues': len(issues),
            'critical': critical,
            'high': high,
            'medium': medium,
            'issues': issues
        }
        print(json.dumps(output, indent=2))
    else:
        if not issues:
            print(f"{Colors.GREEN}No compliance issues found{Colors.END}")
        else:
            print(f"Found {Colors.RED}{len(issues)}{Colors.END} issue(s):\n")
            
            for issue in issues:
                severity_color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.YELLOW,
                    'MEDIUM': Colors.YELLOW
                }.get(issue['severity'], '')
                
                print(f"[{severity_color}{issue['severity']}{Colors.END}] {Colors.CYAN}{issue['sg_name']}{Colors.END} ({issue['sg_id']})")
                print(f"  Protocol: {issue['protocol']} Port: {Colors.YELLOW}{issue['port']}{Colors.END}")
                print(f"  Source: {Colors.RED}{issue['source']}{Colors.END}")
                print(f"  Issue: {issue['description']}")
                print()
        
        print("=" * 70)
        print(f"Summary: {Colors.RED}{critical}{Colors.END} critical, {Colors.YELLOW}{high}{Colors.END} high, {Colors.YELLOW}{medium}{Colors.END} medium")
    
    if args.strict:
        if critical > 0:
            return 2
        elif high > 0:
            return 1
    return 0


def vpc_map(args):
    """Map VPC topology"""
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    print(f"{Colors.CYAN}{Colors.BOLD}VPC Topology Map{Colors.END}")
    print("=" * 70)
    print(f"Region: {Colors.YELLOW}{args.region}{Colors.END}")
    print()
    
    filters = [{'Name': 'vpc-id', 'Values': [args.vpc]}] if args.vpc else []
    vpcs = ec2.describe_vpcs(Filters=filters)['Vpcs']
    
    if not vpcs:
        print(f"{Colors.YELLOW}No VPCs found{Colors.END}")
        return 0
    
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        cidr = vpc['CidrBlock']
        is_default = vpc.get('IsDefault', False)
        
        default_marker = " [DEFAULT]" if is_default else ""
        print(f"VPC: {Colors.CYAN}{vpc_id}{Colors.END} ({Colors.GREEN}{cidr}{Colors.END}){default_marker}")
        
        # Subnets
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        if subnets:
            print(f"  {Colors.YELLOW}Subnets:{Colors.END}")
            for subnet in subnets:
                print(f"    • {Colors.CYAN}{subnet['SubnetId']}{Colors.END} ({Colors.GREEN}{subnet['CidrBlock']}{Colors.END}) - {subnet['AvailabilityZone']} - {Colors.YELLOW}{subnet['AvailableIpAddressCount']}{Colors.END} IPs")
        
        # Route tables
        route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']
        if route_tables:
            print(f"  {Colors.YELLOW}Route Tables:{Colors.END}")
            for rt in route_tables:
                rt_id = rt['RouteTableId']
                assocs = [a.get('SubnetId') for a in rt.get('Associations', []) if 'SubnetId' in a]
                if assocs:
                    print(f"    Route Table: {rt_id} (used by {len(assocs)} subnet(s))")
                    for route in rt.get('Routes', []):
                        dest = route.get('DestinationCidrBlock', route.get('DestinationPrefixListId', 'unknown'))
                        target = route.get('GatewayId') or route.get('NatGatewayId') or route.get('TransitGatewayId') or 'local'
                        state = route.get('State', 'active')
                        
                        if target.startswith('igw-'):
                            route_type = '[IGW]'
                        elif target.startswith('nat-'):
                            route_type = '[NAT]'
                        elif target.startswith('tgw-'):
                            route_type = '[TGW]'
                        else:
                            route_type = '[LOCAL]'
                        
                        print(f"      {route_type} {Colors.GREEN}{dest}{Colors.END} -> {Colors.CYAN}{target}{Colors.END} ({state})")
        
        # Instances
        instances_response = ec2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        instances = []
        for reservation in instances_response['Reservations']:
            instances.extend(reservation['Instances'])
        
        if instances:
            print(f"  {Colors.YELLOW}Instances:{Colors.END}")
            for instance in instances:
                state = instance['State']['Name']
                
                if state == 'running':
                    state_marker = '[RUNNING]'
                elif state == 'stopped':
                    state_marker = '[STOPPED]'
                elif state == 'terminated':
                    state_marker = '[TERMINATED]'
                else:
                    state_marker = f'[{state.upper()}]'
                
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'unnamed')
                
                print(f"    {state_marker} {Colors.CYAN}{name}{Colors.END} ({instance['InstanceId']}) - {Colors.GREEN}{instance.get('PrivateIpAddress', 'N/A')}{Colors.END} - {Colors.YELLOW}{instance['InstanceType']}{Colors.END}")
        
        print()
    
    print("=" * 70)
    return 0


def diff_vpcs(args):
    """Compare two VPCs"""
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    print(f"{Colors.CYAN}{Colors.BOLD}Comparing VPCs{Colors.END}")
    print("=" * 70)
    
    vpcs = ec2.describe_vpcs(VpcIds=[args.vpc1, args.vpc2])['Vpcs']
    if len(vpcs) != 2:
        print(f"{Colors.RED}ERROR: Could not find both VPCs{Colors.END}")
        return 1
    
    vpc1, vpc2 = vpcs[0], vpcs[1]
    
    print(f"VPC 1: {Colors.CYAN}{args.vpc1}{Colors.END} ({Colors.GREEN}{vpc1['CidrBlock']}{Colors.END})")
    print(f"VPC 2: {Colors.CYAN}{args.vpc2}{Colors.END} ({Colors.GREEN}{vpc2['CidrBlock']}{Colors.END})")
    print()
    
    # Compare subnets
    subnets1 = set(s['CidrBlock'] for s in ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [args.vpc1]}])['Subnets'])
    subnets2 = set(s['CidrBlock'] for s in ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [args.vpc2]}])['Subnets'])
    
    print(f"{Colors.YELLOW}Subnets:{Colors.END}")
    print(f"  VPC 1: {Colors.CYAN}{len(subnets1)}{Colors.END} subnet(s)")
    print(f"  VPC 2: {Colors.CYAN}{len(subnets2)}{Colors.END} subnet(s)")
    
    only1 = subnets1 - subnets2
    only2 = subnets2 - subnets1
    
    if only1:
        print(f"  {Colors.RED}[-]{Colors.END} Only in VPC 1: {', '.join(only1)}")
    if only2:
        print(f"  {Colors.GREEN}[+]{Colors.END} Only in VPC 2: {', '.join(only2)}")
    print()
    
    # Compare instances
    inst1 = ec2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [args.vpc1]}])
    inst2 = ec2.describe_instances(Filters=[{'Name': 'vpc-id', 'Values': [args.vpc2]}])
    
    count1 = sum(len(r['Instances']) for r in inst1['Reservations'])
    count2 = sum(len(r['Instances']) for r in inst2['Reservations'])
    
    print(f"{Colors.YELLOW}Instances:{Colors.END}")
    print(f"  VPC 1: {Colors.CYAN}{count1}{Colors.END} instance(s)")
    print(f"  VPC 2: {Colors.CYAN}{count2}{Colors.END} instance(s)")
    print()
    
    print("=" * 70)
    return 0


def estimate_costs(args):
    """Estimate monthly costs"""
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    print(f"{Colors.CYAN}{Colors.BOLD}AWS Cost Estimator{Colors.END}")
    print("=" * 70)
    print(f"Region: {Colors.YELLOW}{args.region}{Colors.END}")
    print()
    
    nat_hourly = 0.045
    tgw_attachment_hourly = 0.05
    hours_per_month = 730
    
    nat_gateways = ec2.describe_nat_gateways()['NatGateways']
    active_nats = sum(1 for nat in nat_gateways if nat['State'] == 'available')
    
    tgws = ec2.describe_transit_gateways().get('TransitGateways', [])
    active_tgws = sum(1 for tgw in tgws if tgw['State'] == 'available')
    
    total_attachments = 0
    for tgw in tgws:
        if tgw['State'] == 'available':
            attachments = ec2.describe_transit_gateway_attachments(
                Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw['TransitGatewayId']]}]
            )['TransitGatewayAttachments']
            total_attachments += sum(1 for att in attachments if att['State'] == 'available')
    
    instances_response = ec2.describe_instances()
    running_instances = sum(
        sum(1 for i in r['Instances'] if i['State']['Name'] == 'running')
        for r in instances_response['Reservations']
    )
    
    print(f"{Colors.YELLOW}Resource Summary:{Colors.END}")
    print(f"  NAT Gateways: {Colors.CYAN}{active_nats}{Colors.END}")
    print(f"  Transit Gateways: {Colors.CYAN}{active_tgws}{Colors.END}")
    print(f"  TGW Attachments: {Colors.CYAN}{total_attachments}{Colors.END}")
    print(f"  Running Instances: {Colors.CYAN}{running_instances}{Colors.END}")
    print()
    
    print(f"{Colors.YELLOW}Estimated Monthly Costs:{Colors.END}")
    
    nat_cost = active_nats * nat_hourly * hours_per_month
    if active_nats > 0:
        print(f"  NAT Gateways: ${nat_cost:.2f}")
    
    tgw_cost = total_attachments * tgw_attachment_hourly * hours_per_month
    if total_attachments > 0:
        print(f"  TGW Attachments: ${tgw_cost:.2f}")
    
    total = nat_cost + tgw_cost
    
    print()
    print("=" * 70)
    print(f"Total (base): {Colors.GREEN}${total:.2f}/month{Colors.END}")
    print("Note: Excludes data transfer, EC2 instances, and other services")
    
    return 0


def analyze_security_groups(args):
    """Detailed security group analysis"""
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    print(f"{Colors.CYAN}{Colors.BOLD}Security Group Analysis{Colors.END}")
    print("=" * 70)
    print(f"Region: {Colors.YELLOW}{args.region}{Colors.END}")
    if args.vpc:
        print(f"VPC: {Colors.YELLOW}{args.vpc}{Colors.END}")
    print()
    
    filters = [{'Name': 'vpc-id', 'Values': [args.vpc]}] if args.vpc else []
    sgs = ec2.describe_security_groups(Filters=filters)['SecurityGroups']
    
    for sg in sgs:
        print(f"Security Group: {Colors.CYAN}{sg['GroupName']}{Colors.END} ({sg['GroupId']})")
        print(f"  VPC: {Colors.GREEN}{sg['VpcId']}{Colors.END}")
        
        if sg.get('IpPermissions'):
            print(f"  {Colors.GREEN}Inbound Rules:{Colors.END}")
            for rule in sg['IpPermissions']:
                protocol = rule.get('IpProtocol', '-1')
                from_port = rule.get('FromPort', 'ALL')
                to_port = rule.get('ToPort', 'ALL')
                port_str = f":{from_port}" if from_port == to_port else f":{from_port}-{to_port}"
                
                for ip_range in rule.get('IpRanges', []):
                    print(f"    • {Colors.YELLOW}{protocol}{Colors.END}{port_str} from {Colors.GREEN}{ip_range['CidrIp']}{Colors.END}")
        
        if sg.get('IpPermissionsEgress'):
            print(f"  {Colors.RED}Outbound Rules:{Colors.END}")
            for rule in sg['IpPermissionsEgress']:
                protocol = rule.get('IpProtocol', '-1')
                for ip_range in rule.get('IpRanges', []):
                    print(f"    • {Colors.YELLOW}{protocol}{Colors.END} to {Colors.GREEN}{ip_range['CidrIp']}{Colors.END}")
        
        print()
    
    print("=" * 70)
    print(f"Total: {len(sgs)} security group(s)")
    return 0


def calculate_subnets(args):
    """Subnet calculator"""
    print(f"{Colors.CYAN}{Colors.BOLD}Subnet Calculator{Colors.END}")
    print("=" * 70)
    print(f"VPC CIDR: {Colors.YELLOW}{args.cidr}{Colors.END}")
    print(f"Subnets: {Colors.CYAN}{args.count}{Colors.END}")
    print()
    
    try:
        network = ipaddress.ip_network(args.cidr)
    except ValueError as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.END}")
        return 1
    
    import math
    bits_needed = math.ceil(math.log2(args.count))
    new_prefix = network.prefixlen + bits_needed
    
    if new_prefix > 28:
        print(f"{Colors.RED}ERROR: Too many subnets - would result in /{new_prefix} (max /28){Colors.END}")
        return 1
    
    original_hosts = 2 ** (32 - network.prefixlen) - 2
    new_hosts = 2 ** (32 - new_prefix) - 2
    
    print(f"Original: /{network.prefixlen} ({original_hosts} hosts)")
    print(f"New subnets: {Colors.GREEN}/{new_prefix} ({new_hosts} hosts each){Colors.END}")
    print()
    
    print(f"{Colors.YELLOW}Subnet Allocations:{Colors.END}")
    
    subnets = list(network.subnets(new_prefix=new_prefix))
    for i, subnet in enumerate(subnets[:args.count]):
        print(f"  Subnet {i+1}: {subnet} ({Colors.CYAN}{new_hosts}{Colors.END} usable hosts)")
    
    print()
    print("=" * 70)
    return 0


def list_vpcs(args):
    """List all VPCs"""
    session, identity = get_session(args.region)
    ec2 = session.client('ec2')
    
    vpcs = ec2.describe_vpcs()['Vpcs']
    
    print(f"{Colors.CYAN}{Colors.BOLD}VPCs in {args.region}{Colors.END}")
    print("=" * 70)
    
    for vpc in vpcs:
        default_str = f" {Colors.YELLOW}(default){Colors.END}" if vpc.get('IsDefault') else ""
        print(f"{Colors.CYAN}{vpc['VpcId']}{Colors.END} - {Colors.GREEN}{vpc['CidrBlock']}{Colors.END}{default_str}")
    
    print(f"\nTotal: {len(vpcs)} VPC(s)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='netkit.py - Network Analysis Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Compliance
    comp = subparsers.add_parser('compliance', help='Check security compliance')
    comp.add_argument('--region', default='us-east-1')
    comp.add_argument('--vpc', help='VPC ID')
    comp.add_argument('--json', action='store_true')
    comp.add_argument('--strict', action='store_true')
    
    # VPC map
    vpc = subparsers.add_parser('vpc-map', help='Map VPC topology')
    vpc.add_argument('--region', default='us-east-1')
    vpc.add_argument('--vpc', help='VPC ID')
    
    # Diff
    diff = subparsers.add_parser('diff', help='Compare two VPCs')
    diff.add_argument('vpc1', help='First VPC ID')
    diff.add_argument('vpc2', help='Second VPC ID')
    diff.add_argument('--region', default='us-east-1')
    
    # Cost
    cost = subparsers.add_parser('cost', help='Estimate costs')
    cost.add_argument('--region', default='us-east-1')
    
    # Security groups
    sg = subparsers.add_parser('sec-groups', help='Analyze security groups')
    sg.add_argument('--region', default='us-east-1')
    sg.add_argument('--vpc', help='VPC ID')
    
    # Subnet calculator
    subnet = subparsers.add_parser('subnet', help='Calculate subnet splits')
    subnet.add_argument('cidr', help='VPC CIDR (e.g., 10.0.0.0/16)')
    subnet.add_argument('--count', type=int, required=True, help='Number of subnets')
    
    # List VPCs
    list_cmd = subparsers.add_parser('list-vpcs', help='List all VPCs')
    list_cmd.add_argument('--region', default='us-east-1')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'compliance':
            return check_compliance(args)
        elif args.command == 'vpc-map':
            return vpc_map(args)
        elif args.command == 'diff':
            return diff_vpcs(args)
        elif args.command == 'cost':
            return estimate_costs(args)
        elif args.command == 'sec-groups':
            return analyze_security_groups(args)
        elif args.command == 'subnet':
            return calculate_subnets(args)
        elif args.command == 'list-vpcs':
            return list_vpcs(args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted{Colors.END}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}ERROR: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
