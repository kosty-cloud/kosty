from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-iam-004", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find console users without MFA", region_scope="global")
def check_all_users_mfa(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag users with console access but no second factor."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    iam.get_login_profile(UserName=user['UserName'])
                except iam.exceptions.NoSuchEntityException:
                    continue
                mfa = iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa['MFADevices']:
                    findings.append(Finding(
                        check_id="aws-iam-004", service="IAM",
                        resource_id=user['UserName'], region=region, account_id=account_id,
                        issue="Console user without MFA",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Account compromise via credential theft", arn=user['Arn'],
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
