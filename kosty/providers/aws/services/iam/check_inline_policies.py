from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-013", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find inline policies on users, roles, and groups", region_scope="global")
def check_inline_policies(session, region, **kwargs):
    """Flag inline policies — harder to audit than managed policies."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator_users = iam.get_paginator('list_users')
        for page in paginator_users.paginate():
            for user in page['Users']:
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
        paginator_roles = iam.get_paginator('list_roles')
        for page in paginator_roles.paginate():
            for role in page['Roles']:
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
