from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-015", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find missing RDS event subscriptions")
def check_no_event_subscription(session, region, **kwargs):
    """Flag accounts with no alerting on database events."""
    rds = session.client('rds', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        subs = rds.describe_event_subscriptions()['EventSubscriptionsList']
        has_sub = any(s.get('SourceType') in ['db-instance', None] and s.get('Enabled') for s in subs)
        if not has_sub:
            findings.append(Finding(
                check_id="aws-rds-015", service="RDS",
                resource_id="rds-event-subscriptions", region=region, account_id=account_id,
                issue="No RDS event subscription for instance events", severity=Severity.MEDIUM,
                finding_type=FindingType.SECURITY, risk="Failovers and config changes go unnoticed",
            ))
    except Exception:
        pass
    return findings
