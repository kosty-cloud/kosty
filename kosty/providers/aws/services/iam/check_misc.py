from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-016", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find Lambda functions sharing execution roles", region_scope="global")
def check_shared_lambda_roles(session, region, **kwargs):
    """Flag functions sharing a role — blast radius expansion on compromise."""
    lam = session.client('lambda', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        role_map = {}
        for page in lam.get_paginator('list_functions').paginate():
            for func in page['Functions']:
                role = func.get('Role', '')
                role_map.setdefault(role, []).append(func['FunctionName'])
        for role_arn, functions in role_map.items():
            if len(functions) > 1:
                for fn in functions:
                    findings.append(Finding(
                        check_id="aws-iam-016", service="IAM",
                        resource_id=fn, region=region, account_id=account_id,
                        issue=f"Shares execution role with {len(functions)-1} other function(s)",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Compromise of one function affects all sharing the role",
                        arn=role_arn,
                    ))
    except Exception:
        pass
    return findings


@register_check(check_id="aws-iam-017", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find users with multiple active access keys", region_scope="global")
def check_multiple_active_keys(session, region, **kwargs):
    """Flag users with more than one active key — increases attack surface."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    keys = iam.list_access_keys(UserName=user['UserName'])
                    active = [k for k in keys['AccessKeyMetadata'] if k['Status'] == 'Active']
                    if len(active) > 1:
                        findings.append(Finding(
                            check_id="aws-iam-017", service="IAM",
                            resource_id=user['UserName'], region=region, account_id=account_id,
                            issue=f"{len(active)} active access keys",
                            severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                            risk="Harder key rotation and increased exposure", arn=user['Arn'],
                        ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
