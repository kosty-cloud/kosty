from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-waf-006",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Check for Bot Control managed rule group",
)
def check_no_bot_control(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag ACLs without automated bot protection."""
    waf = session.client('wafv2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                detail = waf.get_web_acl(Name=acl['Name'], Scope='REGIONAL', Id=acl['Id'])
                has_bot = any(
                    r.get('Statement', {}).get('ManagedRuleGroupStatement', {}).get('Name') == 'AWSManagedRulesBotControlRuleSet'
                    for r in detail['WebACL'].get('Rules', [])
                )
                if not has_bot:
                    findings.append(Finding(
                        check_id="aws-waf-006", service="WAF",
                        resource_id=acl['Name'], region=region, account_id=account_id,
                        issue="No Bot Control rule group configured",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="No protection against scrapers, crawlers, and automated abuse",
                        arn=acl['ARN'],
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
