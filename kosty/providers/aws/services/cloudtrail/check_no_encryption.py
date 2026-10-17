from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-cloudtrail-003",
    service="CloudTrail",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify CloudTrail logs are encrypted with KMS",
)
def check_no_encryption(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag trails relying on default S3 encryption instead of KMS CMK."""
    ct = session.client('cloudtrail', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
