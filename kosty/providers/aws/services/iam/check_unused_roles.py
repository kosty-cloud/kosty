from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-iam-001", service="IAM", provider="aws", finding_type=FindingType.SECURITY, description="Find unused IAM roles (admin roles flagged critical)", region_scope="global")
def check_unused_roles(session, region, days=30, **kwargs):
    """Flag roles not used in 30+ days. Admin roles get critical severity."""
    iam = session.client('iam')
    account_id = get_account_id(session)
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                    continue
                try:
                    detail = iam.get_role(RoleName=role['RoleName'])['Role']
                    last_used = detail.get('RoleLastUsed', {}).get('LastUsedDate')
                    if last_used and last_used.replace(tzinfo=None) >= cutoff:
                        continue
                    has_admin = False
                    for p in iam.list_attached_role_policies(RoleName=role['RoleName']).get('AttachedPolicies', []):
                        if p['PolicyArn'].endswith('/AdministratorAccess'):
                            has_admin = True
                            break
                    findings.append(Finding(
                        check_id="aws-iam-001", service="IAM",
                        resource_id=role['RoleName'], region=region, account_id=account_id,
                        issue=f"{'Unused admin role' if has_admin else 'Unused role'} ({days}+ days)",
                        severity=Severity.CRITICAL if has_admin else Severity.HIGH,
                        finding_type=FindingType.SECURITY,
                        risk="Dormant admin role — prime target for escalation" if has_admin else f"Stale role unused for {days}+ days",
                        arn=role['Arn'],
                    ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
