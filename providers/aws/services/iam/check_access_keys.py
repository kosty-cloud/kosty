from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-iam-005", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find access keys older than 90 days")
def check_old_access_keys(session, region, days=90, **kwargs):
    """Flag keys that haven't been rotated — stale credentials."""
    iam = session.client('iam')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for user in iam.list_users()['Users']:
            try:
                for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                    age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                    if age > days:
                        findings.append(Finding(
                            check_id="aws-iam-005", service="IAM",
                            resource_id=user['UserName'], region=region, account_id=account_id,
                            issue=f"Access key {age} days old (>{days}d threshold)",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Stale credentials increase exposure window", arn=user['Arn'],
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-iam-006", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find active access keys unused for 90+ days")
def check_unused_access_keys(session, region, days=90, **kwargs):
    """Flag dormant keys — attack surface with no business value."""
    iam = session.client('iam')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        for user in iam.list_users()['Users']:
            try:
                for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
                    if key['Status'] != 'Active':
                        continue
                    last = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId']).get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    if not last or last.replace(tzinfo=None) < cutoff:
                        findings.append(Finding(
                            check_id="aws-iam-006", service="IAM",
                            resource_id=user['UserName'], region=region, account_id=account_id,
                            issue=f"Active key unused for {days}+ days",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk="Dormant credentials increase attack surface", arn=user['Arn'],
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
