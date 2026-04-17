import boto3
from typing import List, Dict, Any


class ConfigAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_not_enabled']

    def find_not_enabled(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if AWS Config is enabled and recording"""
        config = session.client('config', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
            status_list = config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']

            if not recorders:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Config',
                    'ResourceId': 'aws-config', 'ResourceName': 'AWS Config',
                    'Issue': 'AWS Config not configured in this region',
                    'type': 'security', 'Risk': 'No configuration change tracking — drift and unauthorized changes go undetected',
                    'severity': 'high', 'check': 'not_enabled'
                })
            else:
                for status in status_list:
                    if not status.get('recording', False):
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'Config',
                            'ResourceId': status['name'], 'ResourceName': status['name'],
                            'Issue': 'AWS Config recorder is not recording',
                            'type': 'security', 'Risk': 'Configuration changes are not being tracked',
                            'severity': 'high', 'check': 'not_enabled'
                        })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking AWS Config: {e}")

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
