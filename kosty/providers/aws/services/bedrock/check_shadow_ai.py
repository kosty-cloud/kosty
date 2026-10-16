import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-004", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Find IAM roles with AI permissions not tagged as approved")
def check_shadow_ai(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag unapproved AI usage across the organization."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                    continue
                has_ai = False
                try:
                    for p in iam.list_attached_role_policies(RoleName=role['RoleName']).get('AttachedPolicies', []):
                        if any(s in p['PolicyName'].lower() for s in ['bedrock', 'sagemaker']):
                            has_ai = True
                            break
                    if not has_ai:
                        for pname in iam.list_role_policies(RoleName=role['RoleName']).get('PolicyNames', []):
                            doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=pname)['PolicyDocument']
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            for stmt in doc.get('Statement', []):
                                actions = stmt.get('Action', [])
                                if not isinstance(actions, list):
                                    actions = [actions]
                                if any('bedrock' in a.lower() or 'sagemaker' in a.lower() for a in actions):
                                    has_ai = True
                                    break
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
                if not has_ai:
                    continue
                tags = {t['Key']: t['Value'] for t in iam.list_role_tags(RoleName=role['RoleName']).get('Tags', [])}
                if not any(k.lower() in ['ai-project', 'ai_project', 'ml-project', 'ml_project', 'genai'] for k in tags):
                    findings.append(Finding(
                        check_id="aws-bedrock-004", service="Bedrock",
                        resource_id=role['RoleName'], region=region, account_id=account_id,
                        issue="IAM role with AI/ML permissions not tagged as approved project",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Potential shadow AI — untracked GenAI spend and data exposure",
                        arn=role['Arn'],
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
