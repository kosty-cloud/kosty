from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-003", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Check if root account has MFA enabled", region_scope="global")
def check_root_mfa(session, region, **kwargs):
    """Flag root without MFA — single factor away from total compromise."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        summary = iam.get_account_summary()
        if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
            findings.append(Finding(
                check_id="aws-iam-003", service="IAM",
                resource_id="root", region=region, account_id=account_id,
                issue="Root account does not have MFA enabled",
                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                risk="Full account takeover if credentials compromised",
            ))
    except Exception:
        pass
    return findings
