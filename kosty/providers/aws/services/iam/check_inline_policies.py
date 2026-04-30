from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-013", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find inline policies on users, roles, and groups")
def check_inline_policies(session, region, **kwargs):
    """Flag inline policies — harder to audit than managed policies."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        for user in iam.list_users()['Users']:
            try:
                for pname in iam.list_user_policies(UserName=user['UserName']).get('PolicyNames', []):
                    findings.append(Finding(
                        check_id="aws-iam-013", service="IAM",
                        resource_id=user['UserName'], region=region, account_id=account_id,
                        issue=f'Inline policy "{pname}" on user',
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Inline policies are harder to audit and reuse", arn=user['Arn'],
                    ))
            except Exception:
                continue
        for role in iam.list_roles()['Roles']:
            if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                continue
            try:
                for pname in iam.list_role_policies(RoleName=role['RoleName']).get('PolicyNames', []):
                    findings.append(Finding(
                        check_id="aws-iam-013", service="IAM",
                        resource_id=role['RoleName'], region=region, account_id=account_id,
                        issue=f'Inline policy "{pname}" on role',
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Inline policies are harder to audit and reuse", arn=role['Arn'],
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
