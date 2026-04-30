import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-014", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find policies granting iam:PassRole with wildcard resource")
def check_passrole_permissions(session, region, **kwargs):
    """Flag policies enabling privilege escalation via role passing."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        for page in iam.get_paginator('list_policies').paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    doc = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
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
                        has_pass = any(a.lower() in ['iam:passrole', 'iam:*', '*'] for a in actions)
                        if has_pass and '*' in resources:
                            findings.append(Finding(
                                check_id="aws-iam-014", service="IAM",
                                resource_id=policy['PolicyName'], region=region, account_id=account_id,
                                issue="iam:PassRole with wildcard resource",
                                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                                risk="Can pass any role to any service — privilege escalation", arn=policy['Arn'],
                            ))
                            break
                except Exception:
                    continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-iam-015", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find policies granting sts:AssumeRole with wildcard")
def check_wildcard_assume_role(session, region, **kwargs):
    """Flag policies allowing assumption of any role in the account."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        for page in iam.get_paginator('list_policies').paginate(Scope='Local'):
            for policy in page['Policies']:
                try:
                    doc = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
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
                        has_assume = any(a.lower() in ['sts:assumerole', 'sts:*', '*'] for a in actions)
                        if has_assume and '*' in resources:
                            findings.append(Finding(
                                check_id="aws-iam-015", service="IAM",
                                resource_id=policy['PolicyName'], region=region, account_id=account_id,
                                issue="sts:AssumeRole with wildcard resource",
                                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                                risk="Can assume any role — full privilege escalation", arn=policy['Arn'],
                            ))
                            break
                except Exception:
                    continue
    except Exception:
        pass
    return findings
