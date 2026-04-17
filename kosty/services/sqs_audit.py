import boto3
from typing import List, Dict, Any


class SQSAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_no_encryption']

    def find_no_encryption(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find SQS queues without server-side encryption"""
        sqs = session.client('sqs', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            queues = sqs.list_queues().get('QueueUrls', [])
            for queue_url in queues:
                try:
                    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['KmsMasterKeyId', 'SqsManagedSseEnabled'])
                    kms_key = attrs.get('Attributes', {}).get('KmsMasterKeyId', '')
                    sse_enabled = attrs.get('Attributes', {}).get('SqsManagedSseEnabled', 'false')

                    if not kms_key and sse_enabled != 'true':
                        queue_name = queue_url.split('/')[-1]
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SQS',
                            'ResourceId': queue_name, 'ResourceName': queue_name,
                            'Issue': 'SQS queue not encrypted',
                            'type': 'security', 'Risk': 'Messages at rest are not protected',
                            'severity': 'medium', 'check': 'no_encryption'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking SQS encryption: {e}")

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
