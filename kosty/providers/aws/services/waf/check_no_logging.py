from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-waf-004",
    service="WAF",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify WAF logging is enabled",
)
def check_no_logging(session, region, **kwargs):
    """Flag ACLs with no logging destination configured."""
    waf = session.client('wafv2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for acl in waf.list_web_acls(Scope='REGIONAL').get('WebACLs', []):
            try:
                waf.get_logging_configuration(ResourceArn=acl['ARN'])
            except waf.exceptions.WAFNonexistentItemException:
                findings.append(Finding(
                    check_id="aws-waf-004", service="WAF",
                    resource_id=acl['Name'], region=region, account_id=account_id,
                    issue="WAF logging not enabled",
                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                    risk="No visibility into blocked or allowed requests",
                    arn=acl['ARN'],
                ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
