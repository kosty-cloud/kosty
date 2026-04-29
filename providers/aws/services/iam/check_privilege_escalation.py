import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


# 21 known privilege escalation patterns
ESCALATION_PATTERNS = {
    'CreatePolicyVersion': {'actions': [['iam:CreatePolicyVersion']], 'risk': 'Can rewrite any policy to grant admin'},
    'SetDefaultPolicyVersion': {'actions': [['iam:SetDefaultPolicyVersion']], 'risk': 'Can activate a more permissive version'},
    'AttachUserPolicy': {'actions': [['iam:AttachUserPolicy']], 'risk': 'Can attach AdministratorAccess to self'},
    'AttachRolePolicy': {'actions': [['iam:AttachRolePolicy']], 'risk': 'Can attach admin to an assumable role'},
    'AttachGroupPolicy': {'actions': [['iam:AttachGroupPolicy']], 'risk': 'Can attach admin to own group'},
    'PutUserPolicy': {'actions': [['iam:PutUserPolicy']], 'risk': 'Can create inline admin policy on self'},
    'PutRolePolicy': {'actions': [['iam:PutRolePolicy']], 'risk': 'Can create inline admin on assumable role'},
    'PutGroupPolicy': {'actions': [['iam:PutGroupPolicy']], 'risk': 'Can create inline admin on own group'},
    'AddUserToGroup': {'actions': [['iam:AddUserToGroup']], 'risk': 'Can add self to admin group'},
    'UpdateAssumeRolePolicy': {'actions': [['iam:UpdateAssumeRolePolicy']], 'risk': 'Can modify trust policy to assume admin role'},
    'CreateLoginProfile': {'actions': [['iam:CreateLoginProfile']], 'risk': 'Can create password for another user'},
    'UpdateLoginProfile': {'actions': [['iam:UpdateLoginProfile']], 'risk': 'Can reset password of another user'},
    'CreateAccessKey': {'actions': [['iam:CreateAccessKey']], 'risk': 'Can create keys for another user'},
    'PassRole+Lambda': {'actions': [['iam:PassRole'], ['lambda:CreateFunction', 'lambda:InvokeFunction']], 'risk': 'Can run Lambda with admin role'},
    'PassRole+LambdaUpdate': {'actions': [['iam:PassRole'], ['lambda:UpdateFunctionCode']], 'risk': 'Can inject code into privileged Lambda'},
    'PassRole+EC2': {'actions': [['iam:PassRole'], ['ec2:RunInstances']], 'risk': 'Can launch EC2 with admin profile'},
    'PassRole+ECS': {'actions': [['iam:PassRole'], ['ecs:RegisterTaskDefinition', 'ecs:RunTask']], 'risk': 'Can run ECS task with admin role'},
    'PassRole+CloudFormation': {'actions': [['iam:PassRole'], ['cloudformation:CreateStack']], 'risk': 'Can deploy stack with admin role'},
    'PassRole+DataPipeline': {'actions': [['iam:PassRole'], ['datapipeline:CreatePipeline']], 'risk': 'Can create pipeline with admin role'},
    'PassRole+Glue': {'actions': [['iam:PassRole'], ['glue:CreateDevEndpoint']], 'risk': 'Can create Glue endpoint with admin role'},
    'AssumeRoleWildcard': {'actions': [['sts:AssumeRole']], 'risk': 'Can assume any role in the account'},
}


@register_check(check_id="aws-iam-018", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Detect privilege escalation paths (21 patterns)", requires_deep=True)
def check_privilege_escalation(session, region, deep=False, **kwargs):
    """Scan all principals for known escalation vectors. Use --deep for SimulatePrincipalPolicy confirmation."""
    iam = session.client('iam')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    principals = []
    try:
        for user in iam.list_users()['Users']:
            principals.append(('User', user['UserName'], user['Arn']))
    except Exception:
        pass
    try:
        for role in iam.list_roles()['Roles']:
            if not role['RoleName'].startswith('aws-') and not role['RoleName'].startswith('AWSServiceRole'):
                principals.append(('Role', role['RoleName'], role['Arn']))
    except Exception:
        pass

    for ptype, name, arn in principals:
        try:
            actions = _get_actions(iam, ptype, name)
            if not actions:
                continue
            for pattern_name, pattern in ESCALATION_PATTERNS.items():
                if _matches(actions, pattern):
                    confirmed = None
                    if deep:
                        confirmed = _simulate(iam, arn, pattern)
                        if confirmed is False:
                            continue
                    findings.append(Finding(
                        check_id="aws-iam-018", service="IAM",
                        resource_id=name, region=region, account_id=account_id,
                        issue=f"{ptype} can escalate via {pattern_name}" + (" [CONFIRMED]" if confirmed else ""),
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk=pattern['risk'], arn=arn,
                    ))
        except Exception:
            continue

    return findings


def _get_actions(iam, ptype, name):
    actions = set()
    try:
        if ptype == 'User':
            for pn in iam.list_user_policies(UserName=name).get('PolicyNames', []):
                _extract(iam.get_user_policy(UserName=name, PolicyName=pn)['PolicyDocument'], actions)
            for p in iam.list_attached_user_policies(UserName=name).get('AttachedPolicies', []):
                if not p['PolicyArn'].startswith('arn:aws:iam::aws:'):
                    _extract_managed(iam, p['PolicyArn'], actions)
        else:
            for pn in iam.list_role_policies(RoleName=name).get('PolicyNames', []):
                _extract(iam.get_role_policy(RoleName=name, PolicyName=pn)['PolicyDocument'], actions)
            for p in iam.list_attached_role_policies(RoleName=name).get('AttachedPolicies', []):
                if not p['PolicyArn'].startswith('arn:aws:iam::aws:'):
                    _extract_managed(iam, p['PolicyArn'], actions)
    except Exception:
        pass
    return actions


def _extract(doc, actions):
    if isinstance(doc, str):
        doc = json.loads(doc)
    for stmt in doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        a = stmt.get('Action', [])
        if not isinstance(a, list):
            a = [a]
        resources = stmt.get('Resource', [])
        if not isinstance(resources, list):
            resources = [resources]
        if '*' in resources:
            actions.update(x.lower() for x in a)


def _extract_managed(iam, arn, actions):
    try:
        pv = iam.get_policy(PolicyArn=arn)
        doc = iam.get_policy_version(PolicyArn=arn, VersionId=pv['Policy']['DefaultVersionId'])['PolicyVersion']['Document']
        _extract(doc, actions)
    except Exception:
        pass


def _matches(actions, pattern):
    for group in pattern['actions']:
        if not all(_action_match(actions, a) for a in group):
            return False
    return True


def _action_match(actions, required):
    req = required.lower()
    svc = req.split(':')[0]
    return req in actions or '*' in actions or f'{svc}:*' in actions


def _simulate(iam, arn, pattern):
    all_actions = [a for group in pattern['actions'] for a in group]
    try:
        result = iam.simulate_principal_policy(PolicySourceArn=arn, ActionNames=all_actions, ResourceArns=['*'])
        return all(r['EvalDecision'] == 'allowed' for r in result['EvaluationResults'])
    except Exception:
        return None
