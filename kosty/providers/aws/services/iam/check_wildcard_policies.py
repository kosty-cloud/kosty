import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-009", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find policies with Action:* or Resource:*", region_scope="global")
def check_wildcard_policies(session, region, **kwargs):
    """Flag overly permissive policies granting god-mode access."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    for pname in iam.list_user_policies(UserName=user['UserName']).get('PolicyNames', []):
                        doc = iam.get_user_policy(UserName=user['UserName'], PolicyName=pname)['PolicyDocument']
                        if _has_wildcard(doc):
                            findings.append(Finding(
                                check_id="aws-iam-009", service="IAM",
                                resource_id=user['UserName'], region=region, account_id=account_id,
                                issue=f"Policy '{pname}' uses Action:* or Resource:*",
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="Privilege escalation risk", arn=user['Arn'],
                            ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings


def _has_wildcard(doc):
    if isinstance(doc, str):
        doc = json.loads(doc)
    for stmt in doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(resources, list):
            resources = [resources]
        if '*' in actions or '*' in resources:
            return True
    return False
