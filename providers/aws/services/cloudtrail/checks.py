"""CloudTrail checks — plugin format.

Demonstrates how a check looks in the new architecture.
Each function is self-registering via @register_check.
"""

from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-cloudtrail-001",
    service="CloudTrail",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify CloudTrail is enabled with multi-region coverage",
)
def check_not_enabled(session, region, **kwargs):
    """Flag accounts without a multi-region CloudTrail trail."""
    ct = session.client('cloudtrail', region_name=region)
    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']
    findings = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False)['trailList']
        multi_region = any(t.get('IsMultiRegionTrail') for t in trails)

        if not trails:
            findings.append(Finding(
                check_id="aws-cloudtrail-001",
                service="CloudTrail",
                resource_id="cloudtrail",
                region=region,
                account_id=account_id,
                issue="No CloudTrail trail configured",
                severity=Severity.CRITICAL,
                finding_type=FindingType.SECURITY,
                risk="Zero audit trail — blind to all API activity",
            ))
        elif not multi_region:
            findings.append(Finding(
                check_id="aws-cloudtrail-001",
                service="CloudTrail",
                resource_id="cloudtrail",
                region=region,
                account_id=account_id,
                issue="No multi-region CloudTrail trail",
                severity=Severity.HIGH,
                finding_type=FindingType.SECURITY,
                risk="Activity in other regions goes unlogged",
            ))
    except Exception as e:
        pass

    return findings


@register_check(
    check_id="aws-cloudtrail-002",
    service="CloudTrail",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify log file validation is enabled",
)
def check_no_log_validation(session, region, **kwargs):
    """Flag trails without log file integrity validation."""
    ct = session.client('cloudtrail', region_name=region)
    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']
    findings = []

    try:
        for trail in ct.describe_trails(includeShadowTrails=False)['trailList']:
            if trail.get('HomeRegion') != region:
                continue
            if not trail.get('LogFileValidationEnabled'):
                findings.append(Finding(
                    check_id="aws-cloudtrail-002",
                    service="CloudTrail",
                    resource_id=trail['Name'],
                    region=region,
                    account_id=account_id,
                    issue="Log file validation disabled",
                    severity=Severity.HIGH,
                    finding_type=FindingType.SECURITY,
                    risk="Tampered logs cannot be detected",
                    arn=trail.get('TrailARN', ''),
                ))
    except Exception:
        pass

    return findings
