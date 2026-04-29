from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-iam-008", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find admin users without MFA")
def check_admin_no_mfa(session, region, **kwargs):
    """Flag users with AdministratorAccess but no MFA — one phish away from total compromise."""
    iam = session.client('iam')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for user in iam.list_users()['Users']:
            try:
                has_admin = False
                for p in iam.list_attached_user_policies(UserName=user['UserName']).get('AttachedPolicies', []):
                    if 'Administrator' in p['PolicyName']:
                        has_admin = True
                        break
                if not has_admin:
                    for g in iam.list_groups_for_user(UserName=user['UserName']).get('Groups', []):
                        for p in iam.list_attached_group_policies(GroupName=g['GroupName']).get('AttachedPolicies', []):
                            if 'Administrator' in p['PolicyName']:
                                has_admin = True
                                break
                        if has_admin:
                            break
                if has_admin and not iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']:
                    findings.append(Finding(
                        check_id="aws-iam-008", service="IAM",
                        resource_id=user['UserName'], region=region, account_id=account_id,
                        issue="Admin access without MFA",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Account takeover via phishing", arn=user['Arn'],
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
