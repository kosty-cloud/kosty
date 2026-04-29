from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-cloudtrail-003",
    service="CloudTrail",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify CloudTrail logs are encrypted with KMS",
)
def check_no_encryption(session, region, **kwargs):
    """Flag trails relying on default S3 encryption instead of KMS CMK."""
    ct = session.client('cloudtrail', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        for trail in ct.describe_trails(includeShadowTrails=False)['trailList']:
            if trail.get('HomeRegion') != region:
                continue
            if not trail.get('KmsKeyId'):
                findings.append(Finding(
                    check_id="aws-cloudtrail-003", service="CloudTrail",
                    resource_id=trail['Name'], region=region, account_id=account_id,
                    issue="CloudTrail logs not encrypted with KMS",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="Audit logs readable if S3 bucket is compromised",
                    arn=trail.get('TrailARN', ''),
                ))
    except Exception:
        pass

    return findings
