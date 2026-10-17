from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-cloudtrail-001",
    service="CloudTrail",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify CloudTrail is enabled with multi-region coverage",
)
def check_not_enabled(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts without a multi-region CloudTrail trail."""
    ct = session.client('cloudtrail', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False)['trailList']
        multi_region = any(t.get('IsMultiRegionTrail') for t in trails)

        if not trails:
            findings.append(Finding(
                check_id="aws-cloudtrail-001", service="CloudTrail",
                resource_id="cloudtrail", region=region, account_id=account_id,
                issue="No CloudTrail trail configured",
                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                risk="Zero audit trail — blind to all API activity",
            ))
        elif not multi_region:
            findings.append(Finding(
                check_id="aws-cloudtrail-001", service="CloudTrail",
                resource_id="cloudtrail", region=region, account_id=account_id,
                issue="No multi-region CloudTrail trail",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="Activity in other regions goes unlogged",
            ))
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
