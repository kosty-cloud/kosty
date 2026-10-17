from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-iam-007", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find inactive users with active keys", region_scope="global")
def check_inactive_users(session: 'boto3.Session', region: str, days=90, **kwargs) -> List[Finding]:
    """Flag users who haven't logged in but still have active credentials."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    keys = iam.list_access_keys(UserName=user['UserName'])
                    if not any(k['Status'] == 'Active' for k in keys['AccessKeyMetadata']):
                        continue
                    last = user.get('PasswordLastUsed')
                    key_last = None
                    for k in keys['AccessKeyMetadata']:
                        try:
                            kl = iam.get_access_key_last_used(AccessKeyId=k['AccessKeyId']).get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            if kl and (not key_last or kl > key_last):
                                key_last = kl
                        except Exception as _exc:
                            handle_check_error(_exc)
                            continue
                    activity = max(filter(None, [last, key_last]), default=None)
                    if not activity or activity.replace(tzinfo=None) < cutoff:
                        findings.append(Finding(
                            check_id="aws-iam-007", service="IAM",
                            resource_id=user['UserName'], region=region, account_id=account_id,
                            issue=f"Inactive {days}+ days with active keys",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk="Dormant account with live credentials", arn=user['Arn'],
                        ))
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
