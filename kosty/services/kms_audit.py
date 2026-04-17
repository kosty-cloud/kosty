import boto3
from typing import List, Dict, Any


class KMSAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_no_key_rotation']

    def find_no_key_rotation(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find customer-managed KMS keys without automatic rotation"""
        kms = session.client('kms', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = kms.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        metadata = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']

                        if metadata.get('KeyManager') != 'CUSTOMER':
                            continue
                        if metadata.get('KeyState') != 'Enabled':
                            continue
                        if metadata.get('KeySpec') not in ['SYMMETRIC_DEFAULT']:
                            continue

                        rotation = kms.get_key_rotation_status(KeyId=key['KeyId'])
                        if not rotation.get('KeyRotationEnabled'):
                            alias = ''
                            try:
                                aliases = kms.list_aliases(KeyId=key['KeyId'])
                                if aliases['Aliases']:
                                    alias = aliases['Aliases'][0]['AliasName']
                            except Exception:
                                pass

                            results.append({
                                'AccountId': account_id, 'Region': region, 'Service': 'KMS',
                                'ResourceId': alias or key['KeyId'],
                                'ResourceName': alias or key['KeyId'],
                                'ARN': metadata['Arn'],
                                'Issue': 'Automatic key rotation not enabled',
                                'type': 'security',
                                'Risk': 'Long-lived encryption keys increase exposure if compromised',
                                'severity': 'medium', 'check': 'no_key_rotation'
                            })
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking KMS key rotation: {e}")

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

    def check_no_key_rotation(self, session, region, **kwargs):
        return self.find_no_key_rotation(session, region, **kwargs)
