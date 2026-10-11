import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-012", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find cross-account roles without ExternalId", region_scope="global")
def check_cross_account_no_external_id(session, region, **kwargs):
    """Flag roles assumable by external accounts without confused deputy protection."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                try:
                    doc = role['AssumeRolePolicyDocument']
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in doc.get('Statement', []):
                        principal = stmt.get('Principal', {})
                        if not isinstance(principal, dict) or 'AWS' not in principal:
                            continue
                        aws_p = principal['AWS']
                        if not isinstance(aws_p, list):
                            aws_p = [aws_p]
                        for p in aws_p:
                            if ':' in str(p) and account_id not in str(p):
                                condition = stmt.get('Condition', {})
                                if not any('ExternalId' in str(c) for c in condition.values()):
                                    findings.append(Finding(
                                        check_id="aws-iam-012", service="IAM",
                                        resource_id=role['RoleName'], region=region, account_id=account_id,
                                        issue="Cross-account role without ExternalId",
                                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                        risk="Confused deputy attack vector", arn=role['Arn'],
                                    ))
                                break
                except Exception:
                    continue
    except Exception:
        pass
    return findings
