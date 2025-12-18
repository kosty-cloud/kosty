import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

class EIPAuditService:
    def __init__(self):
        self.service_name = "EIP"
        self.cost_checks = ['check_unattached_eips', 'check_eips_on_stopped_instances']
        self.security_checks = ['check_eips_with_dangerous_sg_rules']

    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run complete EIP audit (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    
    def check_unattached_eips(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unattached Elastic IPs"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_addresses()
            for eip in response['Addresses']:
                if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'region': region,
                        'Service': self.service_name,
                        'service': 'EIP',
                        'ResourceId': eip.get('AllocationId', eip.get('PublicIp')),
                        'ResourceName': eip.get('PublicIp'),
                        'resource_id': eip.get('AllocationId', eip.get('PublicIp')),
                        'resource_name': eip.get('PublicIp'),
                        'Issue': 'Unattached Elastic IP',
                        'type': 'cost',
                        'check': 'unattached_eips',
                        'Risk': 'HIGH',
                        'severity': 'high',
                        'Description': f"Elastic IP {eip.get('PublicIp')} is unattached",
                        'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:elastic-ip/{eip.get('AllocationId', eip.get('PublicIp'))}",
                        'Details': {
                            'PublicIp': eip.get('PublicIp'),
                            'AllocationId': eip.get('AllocationId'),
                            'Domain': eip.get('Domain')
                        }
                    })
        except Exception as e:
            print(f"Error checking unattached EIPs in {region}: {e}")
        
        return results

    def check_eips_on_stopped_instances(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find EIPs attached to stopped instances"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            eips_response = ec2.describe_addresses()
            instance_ids = [eip['InstanceId'] for eip in eips_response['Addresses'] if 'InstanceId' in eip]
            
            if instance_ids:
                instances_response = ec2.describe_instances(InstanceIds=instance_ids)
                stopped_instances = set()
                
                for reservation in instances_response['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] == 'stopped':
                            stopped_instances.add(instance['InstanceId'])
                
                for eip in eips_response['Addresses']:
                    if 'InstanceId' in eip and eip['InstanceId'] in stopped_instances:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': eip.get('AllocationId', eip.get('PublicIp')),
                            'ResourceName': eip.get('PublicIp'),
                            'Issue': 'EIP attached to stopped instance',
                            'type': 'cost',
                            'Risk': 'HIGH',
                            'severity': 'high',
                            'Description': f"Elastic IP {eip.get('PublicIp')} attached to stopped instance {eip['InstanceId']}",
                            'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:elastic-ip/{eip.get('AllocationId', eip.get('PublicIp'))}",
                            'Details': {
                                'PublicIp': eip.get('PublicIp'),
                                'AllocationId': eip.get('AllocationId'),
                                'InstanceId': eip['InstanceId']
                            }
                        })
        except Exception as e:
            print(f"Error checking EIPs on stopped instances in {region}: {e}")
        
        return results

    def check_eips_with_dangerous_sg_rules(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find EIPs on instances with dangerous security group rules"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            eips_response = ec2.describe_addresses()
            instance_eips = {eip['InstanceId']: eip for eip in eips_response['Addresses'] if 'InstanceId' in eip}
            
            if instance_eips:
                instances_response = ec2.describe_instances(InstanceIds=list(instance_eips.keys()))
                
                for reservation in instances_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        sg_ids = [sg['GroupId'] for sg in instance['SecurityGroups']]
                        
                        sgs_response = ec2.describe_security_groups(GroupIds=sg_ids)
                        has_dangerous_rule = False
                        
                        for sg in sgs_response['SecurityGroups']:
                            for rule in sg.get('IpPermissions', []):
                                for ip_range in rule.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        from_port = rule.get('FromPort', 0)
                                        to_port = rule.get('ToPort', 65535)
                                        
                                        dangerous_ports = [22, 3389, 3306, 5432, 1433, 27017]
                                        if any(port >= from_port and port <= to_port for port in dangerous_ports):
                                            has_dangerous_rule = True
                                            break
                                if has_dangerous_rule:
                                    break
                            if has_dangerous_rule:
                                break
                        
                        if has_dangerous_rule:
                            eip = instance_eips[instance_id]
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': eip.get('AllocationId', eip.get('PublicIp')),
                                'ResourceName': eip.get('PublicIp'),
                                'Issue': 'EIP on instance with dangerous SG rules',
                                'type': 'security',
                                'Risk': 'HIGH',
                                'severity': 'high',
                                'Description': f"Elastic IP {eip.get('PublicIp')} on instance with dangerous security group rules",
                                'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:elastic-ip/{eip.get('AllocationId', eip.get('PublicIp'))}",
                                'Details': {
                                    'PublicIp': eip.get('PublicIp'),
                                    'AllocationId': eip.get('AllocationId'),
                                    'InstanceId': instance_id,
                                    'SecurityGroups': sg_ids
                                }
                            })
        except Exception as e:
            print(f"Error checking EIPs with dangerous SG rules in {region}: {e}")
        
        return results
    
    