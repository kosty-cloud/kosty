from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


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
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        for trail in ct.describe_trails(includeShadowTrails=False)['trailList']:
            if trail.get('HomeRegion') != region:
                continue
            if not trail.get('LogFileValidationEnabled'):
                findings.append(Finding(
                    check_id="aws-cloudtrail-002", service="CloudTrail",
                    resource_id=trail['Name'], region=region, account_id=account_id,
                    issue="Log file validation disabled",
                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                    risk="Tampered logs cannot be detected",
                    arn=trail.get('TrailARN', ''),
                ))
    except Exception:
        pass

    return findings
