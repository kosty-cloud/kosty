import boto3
from typing import List, Dict, Any


class SSMAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_non_compliant_patches']

    def find_non_compliant_patches(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find EC2 instances with missing security patches"""
        ssm = session.client('ssm', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = ssm.get_paginator('describe_instance_patch_states')
            for page in paginator.paginate():
                for instance in page['InstancePatchStates']:
                    missing = instance.get('MissingCount', 0)
                    failed = instance.get('FailedCount', 0)
                    security_missing = instance.get('SecurityNonCompliantCount', 0)

                    if missing > 0 or failed > 0 or security_missing > 0:
                        severity = 'critical' if security_missing > 0 else 'high' if missing > 5 else 'medium'

                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SSM',
                            'ResourceId': instance['InstanceId'],
                            'ResourceName': instance['InstanceId'],
                            'Issue': f'Instance has {missing} missing, {failed} failed, {security_missing} security-critical patches',
                            'type': 'security',
                            'Risk': 'Unpatched vulnerabilities exploitable by known CVEs',
                            'severity': severity, 'check': 'non_compliant_patches',
                            'Details': {
                                'MissingCount': missing,
                                'FailedCount': failed,
                                'SecurityNonCompliantCount': security_missing,
                                'InstalledCount': instance.get('InstalledCount', 0),
                                'OperationEndTime': str(instance.get('OperationEndTime', ''))
                            }
                        })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SSM patch compliance: {e}")

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

    def check_non_compliant_patches(self, session, region, **kwargs):
        return self.find_non_compliant_patches(session, region, **kwargs)
