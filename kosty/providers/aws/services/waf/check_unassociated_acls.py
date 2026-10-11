from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-waf-001",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find Web ACLs not associated with any resource",
)
def check_unassociated_acls(session, region, **kwargs):
    """Flag WAF ACLs that protect nothing."""
    waf = session.client('wafv2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                albs = waf.list_resources_for_web_acl(WebACLArn=acl['ARN'], ResourceType='APPLICATION_LOAD_BALANCER')
                apigw = waf.list_resources_for_web_acl(WebACLArn=acl['ARN'], ResourceType='API_GATEWAY')
                if not albs.get('ResourceArns', []) and not apigw.get('ResourceArns', []):
                    findings.append(Finding(
                        check_id="aws-waf-001", service="WAF",
                        resource_id=acl['Name'], region=region, account_id=account_id,
                        issue="Web ACL not associated with any resource",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="WAF rules have no effect if not attached",
                        arn=acl['ARN'],
                    ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
