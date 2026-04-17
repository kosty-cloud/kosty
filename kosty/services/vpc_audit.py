import boto3
from typing import List, Dict, Any


class VPCAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_no_flow_logs', 'find_default_sg_open']

    def find_no_flow_logs(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find VPCs without Flow Logs enabled"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            flow_logs = ec2.describe_flow_logs()['FlowLogs']
            logged_vpcs = {fl['ResourceId'] for fl in flow_logs if fl.get('ResourceId', '').startswith('vpc-')}

            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                if vpc_id not in logged_vpcs:
                    name = ''
                    for tag in vpc.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break

                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'VPC',
                        'ResourceId': vpc_id, 'ResourceName': name or vpc_id,
                        'Issue': 'VPC Flow Logs not enabled',
                        'type': 'security', 'Risk': 'No network traffic visibility — blind to lateral movement',
                        'severity': 'high', 'check': 'no_flow_logs',
                        'Details': {'VpcId': vpc_id, 'IsDefault': vpc.get('IsDefault', False)}
                    })
        except Exception as e:
            print(f"Error checking VPC Flow Logs: {e}")

        return results

    def find_default_sg_open(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find default security groups with inbound rules"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])

            for sg in sgs['SecurityGroups']:
                if sg.get('IpPermissions'):
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'VPC',
                        'ResourceId': sg['GroupId'], 'ResourceName': f"default ({sg['VpcId']})",
                        'Issue': 'Default security group has inbound rules',
                        'type': 'security', 'Risk': 'Default SG should restrict all traffic — resources added to VPC inherit these rules',
                        'severity': 'medium', 'check': 'default_sg_open',
                        'Details': {'VpcId': sg['VpcId'], 'InboundRuleCount': len(sg['IpPermissions'])}
                    })
        except Exception as e:
            print(f"Error checking default SG: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return []

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.security_audit(session, region, config_manager=config_manager, **kwargs)

    def check_no_flow_logs(self, session, region, **kwargs):
        return self.find_no_flow_logs(session, region, **kwargs)

    def check_default_sg_open(self, session, region, **kwargs):
        return self.find_default_sg_open(session, region, **kwargs)
