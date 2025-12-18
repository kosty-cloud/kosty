import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class NATAuditService:
    def __init__(self):
        self.service_name = "NAT"
        self.cost_checks = ['find_unused_nat_gateways', 'find_redundant_nat_gateways']
        self.security_checks = []  # NAT Gateway has no security checks

    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related NAT Gateway audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related NAT Gateway audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all NAT Gateway audits"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results

    def find_unused_nat_gateways(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find NAT Gateways with <1MB data transfer in X days"""
        ec2 = session.client('ec2', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            response = ec2.describe_nat_gateways()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for nat_gw in response['NatGateways']:
                if nat_gw['State'] != 'available':
                    continue
                
                try:
                    # Get bytes processed metrics
                    metrics_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/NATGateway',
                        MetricName='BytesOutToDestination',
                        Dimensions=[
                            {'Name': 'NatGatewayId', 'Value': nat_gw['NatGatewayId']}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    
                    total_bytes = sum(point['Sum'] for point in metrics_response['Datapoints'])
                    total_mb = total_bytes / (1024 * 1024)  # Convert to MB
                    
                    if total_mb < 1:  # Less than 1MB
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'region': region,
                            'Service': self.service_name,
                            'service': 'NAT',
                            'ResourceId': nat_gw['NatGatewayId'],
                            'resource_id': nat_gw['NatGatewayId'],
                            'resource_name': nat_gw['NatGatewayId'],
                            'ResourceArn': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:natgateway/{nat_gw['NatGatewayId']}",
                            'Issue': f'NAT Gateway with <1MB data transfer {days} days',
                            'type': 'cost',
                            'check': 'unused_nat_gateways',
                            'Risk': 'Waste $130/mo ($1,560/year)',
                            'severity': 'high',
                            'Details': {
                                'NatGatewayId': nat_gw['NatGatewayId'],
                                'SubnetId': nat_gw.get('SubnetId'),
                                'VpcId': nat_gw.get('VpcId'),
                                'DataTransferMB': round(total_mb, 2),
                                'State': nat_gw['State']
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results

    def find_redundant_nat_gateways(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find multiple NAT Gateways per AZ (should be shared)"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            # Get NAT Gateways
            nat_response = ec2.describe_nat_gateways()
            active_nats = [nat for nat in nat_response['NatGateways'] if nat['State'] == 'available']
            
            if len(active_nats) <= 1:
                return results
            
            # Get subnet details to determine AZs
            subnet_ids = [nat['SubnetId'] for nat in active_nats]
            subnets_response = ec2.describe_subnets(SubnetIds=subnet_ids)
            subnet_az_map = {subnet['SubnetId']: subnet['AvailabilityZone'] for subnet in subnets_response['Subnets']}
            
            # Group NAT Gateways by AZ
            az_nats = {}
            for nat in active_nats:
                az = subnet_az_map.get(nat['SubnetId'])
                if az:
                    if az not in az_nats:
                        az_nats[az] = []
                    az_nats[az].append(nat)
            
            # Check for multiple NATs in same AZ
            for az, nats in az_nats.items():
                if len(nats) > 1:
                    for nat in nats[1:]:  # Skip first one, flag the rest as redundant
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': nat['NatGatewayId'],
                            'ResourceArn': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:natgateway/{nat['NatGatewayId']}",
                            'Issue': 'NAT Gateway per AZ (should be shared)',
                            'type': 'cost',
                            'Risk': 'Waste 50% (redundant)',
                            'severity': 'medium',
                            'Details': {
                                'NatGatewayId': nat['NatGatewayId'],
                                'AvailabilityZone': az,
                                'SubnetId': nat.get('SubnetId'),
                                'VpcId': nat.get('VpcId'),
                                'TotalNATsInAZ': len(nats)
                            }
                        })
        except Exception as e:
            pass
        
        return results

    # Individual check aliases
    def check_unused_nat_gateways(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unused_nat_gateways(session, region, days, **kwargs)
    
    def check_redundant_nat_gateways(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_redundant_nat_gateways(session, region, **kwargs)