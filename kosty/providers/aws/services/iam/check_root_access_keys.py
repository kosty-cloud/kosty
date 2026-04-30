from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-002", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Check if root account has access keys")
def check_root_access_keys(session, region, **kwargs):
    """Flag root access keys — should never exist."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        summary = iam.get_account_summary()
        if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
            findings.append(Finding(
                check_id="aws-iam-002", service="IAM",
                resource_id="root", region=region, account_id=account_id,
                issue="Root account has access keys",
                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                risk="Full account takeover if keys are compromised",
            ))
    except Exception:
        pass
    return findings
