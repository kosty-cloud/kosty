import boto3
from typing import List, Dict, Any


class SNSAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_no_encryption']

    def find_no_encryption(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find SNS topics without server-side encryption"""
        sns = session.client('sns', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for topic in sns.list_topics().get('Topics', []):
                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic['TopicArn'])['Attributes']
                    kms_key = attrs.get('KmsMasterKeyId', '')
                    if not kms_key:
                        topic_name = topic['TopicArn'].split(':')[-1]
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SNS',
                            'ResourceId': topic_name, 'ResourceName': topic_name,
                            'ARN': topic['TopicArn'],
                            'Issue': 'SNS topic not encrypted',
                            'type': 'security', 'Risk': 'Messages in transit and at rest are not protected',
                            'severity': 'medium', 'check': 'no_encryption'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking SNS encryption: {e}")

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

    def check_no_encryption(self, session, region, **kwargs):
        return self.find_no_encryption(session, region, **kwargs)
