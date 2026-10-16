from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-waf-003",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Check for rate-based rules (DDoS/brute-force protection)",
)
def check_no_rate_based_rule(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag ACLs without any rate limiting — exposed to volumetric attacks."""
    waf = session.client('wafv2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                detail = waf.get_web_acl(Name=acl['Name'], Scope='REGIONAL', Id=acl['Id'])
                has_rate = any('RateBasedStatement' in r.get('Statement', {}) for r in detail['WebACL'].get('Rules', []))
                if not has_rate:
                    findings.append(Finding(
                        check_id="aws-waf-003", service="WAF",
                        resource_id=acl['Name'], region=region, account_id=account_id,
                        issue="No rate-based rule — DDoS/brute-force exposure",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="No automated throttling against volumetric attacks",
                        arn=acl['ARN'],
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
