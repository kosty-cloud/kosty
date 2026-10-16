from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-cloudwatch-001",
    service="CloudWatch",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find log groups without retention policy",
)
def check_log_groups_without_retention(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag log groups growing indefinitely with no expiration."""
    logs = session.client('logs', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
