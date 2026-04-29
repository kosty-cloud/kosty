from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-sns-001",
    service="SNS",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find SNS topics without server-side encryption",
)
def check_no_encryption(session, region, **kwargs):
    """Flag topics without KMS encryption configured."""
    sns = session.client('sns', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        for topic in sns.list_topics().get('Topics', []):
            try:
                attrs = sns.get_topic_attributes(TopicArn=topic['TopicArn'])['Attributes']
                if not attrs.get('KmsMasterKeyId', ''):
                    findings.append(Finding(
                        check_id="aws-sns-001", service="SNS",
                        resource_id=topic['TopicArn'].split(':')[-1],
                        region=region, account_id=account_id,
                        issue="SNS topic not encrypted",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Messages at rest are not protected",
                        arn=topic['TopicArn'],
                    ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
