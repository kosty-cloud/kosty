from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-cloudwatch-002",
    service="CloudWatch",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find alarms with no state changes in 30+ days",
)
def check_unused_alarms(session, region, days=30, **kwargs):
    """Flag alarms that haven't triggered — possibly misconfigured."""
    cw = session.client('cloudwatch', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        cutoff = datetime.utcnow() - timedelta(days=days)
        paginator = cw.get_paginator('describe_alarms')
        for page in paginator.paginate():
            for alarm in page['MetricAlarms']:
                updated = alarm.get('StateUpdatedTimestamp')
                if updated and updated.replace(tzinfo=None) < cutoff:
                    findings.append(Finding(
                        check_id="aws-cloudwatch-002", service="CloudWatch",
                        resource_id=alarm['AlarmName'], region=region, account_id=account_id,
                        issue=f"Alarm unchanged for {days}+ days",
                        severity=Severity.LOW, finding_type=FindingType.SECURITY,
                        risk="Possibly stale or misconfigured alarm",
                        arn=alarm.get('AlarmArn', ''),
                    ))
    except Exception:
        pass

    return findings
