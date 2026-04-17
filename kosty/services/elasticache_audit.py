import boto3
from typing import List, Dict, Any


class ElastiCacheAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_no_encryption_at_rest', 'find_no_encryption_in_transit']

    def find_no_encryption_at_rest(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find ElastiCache clusters without encryption at rest"""
        ec = session.client('elasticache', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            # Redis replication groups
            paginator = ec.get_paginator('describe_replication_groups')
            for page in paginator.paginate():
                for rg in page['ReplicationGroups']:
                    if not rg.get('AtRestEncryptionEnabled', False):
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'ElastiCache',
                            'ResourceId': rg['ReplicationGroupId'],
                            'ResourceName': rg.get('Description', rg['ReplicationGroupId']),
                            'ARN': rg.get('ARN', ''),
                            'Issue': 'Encryption at rest not enabled',
                            'type': 'security',
                            'Risk': 'Cached data readable if underlying storage is compromised',
                            'severity': 'high', 'check': 'no_encryption_at_rest',
                            'Details': {'Engine': 'redis', 'Status': rg.get('Status')}
                        })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking ElastiCache encryption at rest: {e}")

        return results

    def find_no_encryption_in_transit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find ElastiCache clusters without encryption in transit"""
        ec = session.client('elasticache', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = ec.get_paginator('describe_replication_groups')
            for page in paginator.paginate():
                for rg in page['ReplicationGroups']:
                    if not rg.get('TransitEncryptionEnabled', False):
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'ElastiCache',
                            'ResourceId': rg['ReplicationGroupId'],
                            'ResourceName': rg.get('Description', rg['ReplicationGroupId']),
                            'ARN': rg.get('ARN', ''),
                            'Issue': 'Encryption in transit not enabled',
                            'type': 'security',
                            'Risk': 'Data between app and cache transmitted in plaintext',
                            'severity': 'high', 'check': 'no_encryption_in_transit',
                            'Details': {'Engine': 'redis', 'Status': rg.get('Status')}
                        })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking ElastiCache encryption in transit: {e}")

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

    def check_no_encryption_at_rest(self, session, region, **kwargs):
        return self.find_no_encryption_at_rest(session, region, **kwargs)

    def check_no_encryption_in_transit(self, session, region, **kwargs):
        return self.find_no_encryption_in_transit(session, region, **kwargs)
