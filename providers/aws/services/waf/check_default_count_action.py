from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-waf-005",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Ensure critical managed rules are not set to Count mode",
)
def check_default_count_action(session, region, **kwargs):
    """Flag ACLs where critical rule groups log but don't block."""
    waf = session.client('wafv2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    critical_groups = ['AWSManagedRulesCommonRuleSet', 'AWSManagedRulesSQLiRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet']

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                detail = waf.get_web_acl(Name=acl['Name'], Scope='REGIONAL', Id=acl['Id'])
                for rule in detail['WebACL'].get('Rules', []):
                    mgr = rule.get('Statement', {}).get('ManagedRuleGroupStatement', {})
                    if mgr.get('Name') in critical_groups:
                        action = rule.get('OverrideAction', {})
                        if 'Count' in action or 'count' in action:
                            findings.append(Finding(
                                check_id="aws-waf-005", service="WAF",
                                resource_id=acl['Name'], region=region, account_id=account_id,
                                issue=f'Rule group "{mgr["Name"]}" set to Count instead of Block',
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="Attacks logged but not blocked — false sense of security",
                                arn=acl['ARN'],
                            ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
