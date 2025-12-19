import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any

class SGAuditService:
    def __init__(self):
        self.cost_checks = ['find_unused_security_groups']
        self.security_checks = ['find_ssh_rdp_open', 'find_database_ports_open', 'find_all_ports_open']
        self.other_checks = ['find_complex_security_groups']

    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager))
        return results

    def other_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all other-related audits"""
        results = []
        for check in self.other_checks:
            method = getattr(self, check)
            if check == 'find_complex_security_groups':
                results.extend(method(session, region, config_manager=config_manager, **kwargs))
            else:
                results.extend(method(session, region, config_manager=config_manager))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security + other)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        results.extend(self.other_audit(session, region, **kwargs))
        return results

    def find_ssh_rdp_open(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find security groups with SSH/RDP open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            if (22 >= from_port and 22 <= to_port) or (3389 >= from_port and 3389 <= to_port):
                                results.append({
                                    'AccountId': session.client('sts').get_caller_identity()['Account'],
                                    'ResourceName': sg['GroupName'],
                                    'Region': region,
                                    'Service': 'SG',
                                    'ResourceId': sg['GroupId'],
                                    'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:security-group/{sg['GroupId']}",
                                    'Issue': 'Port 22/3389 open to 0.0.0.0/0',
                                    'type': 'security',
                                    'Risk': 'Brute force attacks',
                                    'severity': 'critical',
                                    'Details': {
                                        'GroupName': sg['GroupName'],
                                        'FromPort': from_port,
                                        'ToPort': to_port,
                                        'Protocol': rule.get('IpProtocol')
                                    }
                                })
                                break
        except Exception as e:
            pass
        
        return results

    def find_database_ports_open(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find security groups with database ports open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_security_groups()
            db_ports = [3306, 5432, 1433, 27017]
            
            for sg in response['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            if any(port >= from_port and port <= to_port for port in db_ports):
                                results.append({
                                    'AccountId': session.client('sts').get_caller_identity()['Account'],
                                    'ResourceName': sg['GroupName'],
                                    'Region': region,
                                    'Service': 'SG',
                                    'ResourceId': sg['GroupId'],
                                    'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:security-group/{sg['GroupId']}",
                                    'Issue': 'Database ports open to 0.0.0.0/0',
                                    'type': 'security',
                                    'Risk': 'Unauthorized DB access',
                                    'severity': 'critical',
                                    'Details': {
                                        'GroupName': sg['GroupName'],
                                        'FromPort': from_port,
                                        'ToPort': to_port,
                                        'Protocol': rule.get('IpProtocol')
                                    }
                                })
                                break
        except Exception as e:
            pass
        
        return results

    def find_all_ports_open(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find security groups with all ports open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            if from_port == 0 and to_port == 65535:
                                results.append({
                                    'AccountId': session.client('sts').get_caller_identity()['Account'],
                                    'ResourceName': sg['GroupName'],
                                    'Region': region,
                                    'Service': 'SG',
                                    'ResourceId': sg['GroupId'],
                                    'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:security-group/{sg['GroupId']}",
                                    'Issue': 'All ports open (0-65535) to 0.0.0.0/0',
                                    'type': 'security',
                                    'Risk': 'Complete exposure',
                                    'severity': 'critical',
                                    'Details': {
                                        'GroupName': sg['GroupName'],
                                        'Protocol': rule.get('IpProtocol')
                                    }
                                })
                                break
        except Exception as e:
            pass
        
        return results

    def find_unused_security_groups(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find unused security groups"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            # Get all security groups
            sgs_response = ec2.describe_security_groups()
            all_sgs = {sg['GroupId']: sg for sg in sgs_response['SecurityGroups']}
            
            # Get security groups in use by instances
            used_sgs = set()
            instances_response = ec2.describe_instances()
            for reservation in instances_response['Reservations']:
                for instance in reservation['Instances']:
                    for sg in instance.get('SecurityGroups', []):
                        used_sgs.add(sg['GroupId'])
            
            # Get security groups in use by load balancers
            try:
                elbv2 = session.client('elbv2', region_name=region)
                lbs_response = elbv2.describe_load_balancers()
                for lb in lbs_response['LoadBalancers']:
                    for sg_id in lb.get('SecurityGroups', []):
                        used_sgs.add(sg_id)
            except Exception:
                pass
            
            # Find unused security groups
            for sg_id, sg in all_sgs.items():
                if sg_id not in used_sgs and sg['GroupName'] != 'default':
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'ResourceName': sg['GroupName'],
                        'Region': region,
                        'Service': 'SG',
                        'ResourceId': sg_id,
                        'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:security-group/{sg_id}",
                        'Issue': 'Unused security group (no attachments)',
                        'type': 'cost',
                        'Risk': 'Configuration drift',
                        'severity': 'low',
                        'Details': {
                            'GroupName': sg['GroupName'],
                            'Description': sg.get('Description', '')
                        }
                    })
        except Exception as e:
            pass
        
        return results

    def find_complex_security_groups(self, session: boto3.Session, region: str, rule_threshold: int = 50, config_manager=None) -> List[Dict[str, Any]]:
        """Find security groups with >rule_threshold rules"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                rule_count = len(sg.get('IpPermissions', [])) + len(sg.get('IpPermissionsEgress', []))
                
                if rule_count > rule_threshold:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'ResourceName': sg['GroupName'],
                        'Region': region,
                        'Service': 'SG',
                        'ResourceId': sg['GroupId'],
                        'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:security-group/{sg['GroupId']}",
                        'Issue': f'Security group with >{rule_threshold} rules',
                        'type': 'other',
                        'Risk': 'Complex troubleshooting',
                        'severity': 'low',
                        'Details': {
                            'GroupName': sg['GroupName'],
                            'RuleCount': rule_count,
                            'Threshold': rule_threshold
                        }
                    })
        except Exception as e:
            pass
        
        return results

    # Individual check aliases
    def check_unused_groups(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unused_security_groups(session, region)
    
    def check_ssh_rdp_open(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_ssh_rdp_open(session, region)
    
    def check_database_ports_open(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_database_ports_open(session, region)
    
    def check_all_ports_open(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_all_ports_open(session, region)
    
    def check_complex_security_groups(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_complex_security_groups(session, region, **kwargs)