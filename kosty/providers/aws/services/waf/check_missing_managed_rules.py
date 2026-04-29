from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-waf-002",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify presence of AWS Managed Rules (CRS, IP Rep, SQLi, Known Bad Inputs)",
)
def check_missing_managed_rules(session, region, **kwargs):
    """Flag ACLs missing critical managed rule groups."""
    waf = session.client('wafv2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    required = {
        'AWSManagedRulesCommonRuleSet': 'Core Rule Set',
        'AWSManagedRulesAmazonIpReputationList': 'IP Reputation',
        'AWSManagedRulesSQLiRuleSet': 'SQLi Rule Set',
        'AWSManagedRulesKnownBadInputsRuleSet': 'Known Bad Inputs',
    }

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                detail = waf.get_web_acl(Name=acl['Name'], Scope='REGIONAL', Id=acl['Id'])
                rules = detail['WebACL'].get('Rules', [])
                present = set()
                for rule in rules:
                    mgr = rule.get('Statement', {}).get('ManagedRuleGroupStatement', {})
                    if mgr.get('VendorName') == 'AWS':
                        present.add(mgr.get('Name'))

                for group, label in required.items():
                    if group not in present:
                        findings.append(Finding(
                            check_id="aws-waf-002", service="WAF",
                            resource_id=acl['Name'], region=region, account_id=account_id,
                            issue=f"Missing AWS Managed Rule: {label}",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk=f"No protection from {label} attack vectors",
                            arn=acl['ARN'],
                        ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
