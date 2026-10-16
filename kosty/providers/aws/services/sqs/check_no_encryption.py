from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-sqs-001",
    service="SQS",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find SQS queues without server-side encryption",
)
def check_no_encryption(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag queues without KMS or SQS-managed encryption."""
    sqs = session.client('sqs', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for queue_url in sqs.list_queues().get('QueueUrls', []):
            try:
                attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['KmsMasterKeyId', 'SqsManagedSseEnabled'])
                kms = attrs.get('Attributes', {}).get('KmsMasterKeyId', '')
                sse = attrs.get('Attributes', {}).get('SqsManagedSseEnabled', 'false')
                if not kms and sse != 'true':
                    findings.append(Finding(
                        check_id="aws-sqs-001", service="SQS",
                        resource_id=queue_url.split('/')[-1],
                        region=region, account_id=account_id,
                        issue="SQS queue not encrypted",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Messages at rest are not protected",
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
