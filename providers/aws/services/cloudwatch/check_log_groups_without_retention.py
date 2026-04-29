from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-cloudwatch-001",
    service="CloudWatch",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find log groups without retention policy",
)
def check_log_groups_without_retention(session, region, **kwargs):
    """Flag log groups growing indefinitely with no expiration."""
    logs = session.client('logs', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for lg in page['logGroups']:
                if not lg.get('retentionInDays'):
                    stored_gb = round(lg.get('storedBytes', 0) / (1024**3), 2)
                    findings.append(Finding(
                        check_id="aws-cloudwatch-001", service="CloudWatch",
                        resource_id=lg['logGroupName'], region=region, account_id=account_id,
                        issue=f"No retention policy ({stored_gb} GB stored)",
                        severity=Severity.HIGH if stored_gb > 1 else Severity.MEDIUM,
                        finding_type=FindingType.SECURITY,
                        risk="Logs grow indefinitely — cost and compliance risk",
                        arn=lg.get('arn', ''),
                    ))
    except Exception:
        pass

    return findings
