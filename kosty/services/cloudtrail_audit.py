import boto3
from typing import List, Dict, Any


class CloudTrailAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = [
            'find_not_enabled', 'find_no_log_validation', 'find_no_encryption'
        ]

    def find_not_enabled(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if CloudTrail is enabled with multi-region coverage"""
        ct = session.client('cloudtrail', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            trails = ct.describe_trails(includeShadowTrails=False)['trailList']
            multi_region = any(t.get('IsMultiRegionTrail') for t in trails)

            if not trails:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'CloudTrail',
                    'ResourceId': 'cloudtrail', 'ResourceName': 'CloudTrail',
                    'Issue': 'No CloudTrail trail configured',
                    'type': 'security', 'Risk': 'Zero audit trail — blind to all API activity',
                    'severity': 'critical', 'check': 'not_enabled'
                })
            elif not multi_region:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'CloudTrail',
                    'ResourceId': 'cloudtrail', 'ResourceName': 'CloudTrail',
                    'Issue': 'No multi-region CloudTrail trail',
                    'type': 'security', 'Risk': 'Activity in other regions goes unlogged',
                    'severity': 'high', 'check': 'not_enabled'
                })
        except Exception as e:
            print(f"Error checking CloudTrail: {e}")

        return results

    def find_no_log_validation(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if log file validation is enabled"""
        ct = session.client('cloudtrail', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for trail in ct.describe_trails(includeShadowTrails=False)['trailList']:
                if trail.get('HomeRegion') != region:
                    continue
                if not trail.get('LogFileValidationEnabled'):
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'CloudTrail',
                        'ResourceId': trail['Name'], 'ResourceName': trail['Name'],
                        'ARN': trail.get('TrailARN'),
                        'Issue': 'Log file validation disabled',
                        'type': 'security', 'Risk': 'Tampered logs cannot be detected',
                        'severity': 'high', 'check': 'no_log_validation'
                    })
        except Exception as e:
            print(f"Error checking CloudTrail log validation: {e}")

        return results

    def find_no_encryption(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if CloudTrail logs are encrypted with KMS"""
        ct = session.client('cloudtrail', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for trail in ct.describe_trails(includeShadowTrails=False)['trailList']:
                if trail.get('HomeRegion') != region:
                    continue
                if not trail.get('KmsKeyId'):
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'CloudTrail',
                        'ResourceId': trail['Name'], 'ResourceName': trail['Name'],
                        'ARN': trail.get('TrailARN'),
                        'Issue': 'CloudTrail logs not encrypted with KMS',
                        'type': 'security', 'Risk': 'Audit logs readable if S3 bucket is compromised',
                        'severity': 'medium', 'check': 'no_encryption'
                    })
        except Exception as e:
            print(f"Error checking CloudTrail encryption: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return []

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results

    def check_not_enabled(self, session, region, **kwargs):
        return self.find_not_enabled(session, region, **kwargs)

    def check_no_log_validation(self, session, region, **kwargs):
        return self.find_no_log_validation(session, region, **kwargs)

    def check_no_encryption(self, session, region, **kwargs):
        return self.find_no_encryption(session, region, **kwargs)
