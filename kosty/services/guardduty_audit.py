import boto3
from typing import List, Dict, Any


class GuardDutyAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_not_enabled']

    def find_not_enabled(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if GuardDuty is enabled in the region"""
        gd = session.client('guardduty', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            detectors = gd.list_detectors()['DetectorIds']

            if not detectors:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'GuardDuty',
                    'ResourceId': 'guardduty', 'ResourceName': 'GuardDuty',
                    'Issue': 'GuardDuty not enabled in this region',
                    'type': 'security', 'Risk': 'No threat detection — compromised instances, crypto mining, and credential exfiltration go undetected',
                    'severity': 'high', 'check': 'not_enabled'
                })
            else:
                for detector_id in detectors:
                    detector = gd.get_detector(DetectorId=detector_id)
                    if detector.get('Status') != 'ENABLED':
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'GuardDuty',
                            'ResourceId': detector_id, 'ResourceName': f'Detector {detector_id}',
                            'Issue': 'GuardDuty detector is disabled',
                            'type': 'security', 'Risk': 'Threat detection suspended',
                            'severity': 'high', 'check': 'not_enabled'
                        })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking GuardDuty: {e}")

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

    def check_not_enabled(self, session, region, **kwargs):
        return self.find_not_enabled(session, region, **kwargs)
