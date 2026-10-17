from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-rds-015", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find missing RDS event subscriptions")
def check_no_event_subscription(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts with no alerting on database events."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
