from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-iam-010", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find weak password policy", region_scope="global")
def check_weak_password_policy(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts with insufficient password complexity requirements."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
        except iam.exceptions.NoSuchEntityException:
            findings.append(Finding(
                check_id="aws-iam-010", service="IAM",
                resource_id="password-policy", region=region, account_id=account_id,
                issue="No password policy configured",
                severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                risk="Allows weak passwords",
            ))
            return findings
        weak = []
        if policy.get('MinimumPasswordLength', 0) < 8:
            weak.append("min length < 8")
        if not policy.get('RequireUppercaseCharacters'):
            weak.append("no uppercase")
        if not policy.get('RequireNumbers'):
            weak.append("no numbers")
        if not policy.get('RequireSymbols'):
            weak.append("no symbols")
        if weak:
            findings.append(Finding(
                check_id="aws-iam-010", service="IAM",
                resource_id="password-policy", region=region, account_id=account_id,
                issue=f"Weak password policy: {', '.join(weak)}",
                severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                risk="Allows easily guessable passwords",
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-iam-011", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find missing password rotation policy", region_scope="global")
def check_no_password_rotation(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts without forced password expiration."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
            max_age = policy.get('MaxPasswordAge')
            if not max_age or max_age > 90:
                findings.append(Finding(
                    check_id="aws-iam-011", service="IAM",
                    resource_id="password-policy", region=region, account_id=account_id,
                    issue=f"Password rotation not enforced (max age: {max_age or 'none'})",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="Compromised passwords remain valid indefinitely",
                ))
        except iam.exceptions.NoSuchEntityException:
            findings.append(Finding(
                check_id="aws-iam-011", service="IAM",
                resource_id="password-policy", region=region, account_id=account_id,
                issue="No password policy — no rotation enforced",
                severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                risk="Passwords never expire",
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
