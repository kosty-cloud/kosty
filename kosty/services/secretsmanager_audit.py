import boto3
from typing import List, Dict, Any
from datetime import datetime, timedelta


class SecretsManagerAuditService:
    def __init__(self):
        self.cost_checks = ['find_unused_secrets']
        self.security_checks = ['find_no_rotation']

    def find_unused_secrets(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find secrets never accessed but billed at $0.40/mo each"""
        sm = session.client('secretsmanager', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            cutoff = datetime.now() - timedelta(days=days)
            paginator = sm.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    last_accessed = secret.get('LastAccessedDate')
                    is_unused = not last_accessed or last_accessed.replace(tzinfo=None) < cutoff

                    if is_unused:
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SecretsManager',
                            'ResourceId': secret['Name'], 'ResourceName': secret['Name'],
                            'ARN': secret['ARN'],
                            'Issue': f'Secret unused for {days}+ days ($0.40/mo)',
                            'type': 'cost', 'Risk': 'Waste $0.40/mo per unused secret',
                            'severity': 'low', 'check': 'unused_secrets',
                            'monthly_savings': 0.40,
                            'Details': {
                                'LastAccessed': last_accessed.isoformat() if last_accessed else 'Never',
                                'CreatedDate': secret.get('CreatedDate', '').isoformat() if secret.get('CreatedDate') else ''
                            }
                        })
        except Exception as e:
            print(f"Error checking unused secrets: {e}")

        return results

    def find_no_rotation(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find secrets without automatic rotation enabled"""
        sm = session.client('secretsmanager', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = sm.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    if not secret.get('RotationEnabled', False):
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SecretsManager',
                            'ResourceId': secret['Name'], 'ResourceName': secret['Name'],
                            'ARN': secret['ARN'],
                            'Issue': 'Secret rotation not enabled',
                            'type': 'security', 'Risk': 'Static secrets increase exposure window if leaked',
                            'severity': 'medium', 'check': 'no_rotation'
                        })
        except Exception as e:
            print(f"Error checking secret rotation: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results

    def check_unused_secrets(self, session, region, **kwargs):
        return self.find_unused_secrets(session, region, **kwargs)

    def check_no_rotation(self, session, region, **kwargs):
        return self.find_no_rotation(session, region, **kwargs)
