from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-secretsmanager-002",
    service="SecretsManager",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find secrets without automatic rotation enabled",
)
def check_no_rotation(session, region, **kwargs):
    """Flag secrets relying on manual rotation."""
    sm = session.client('secretsmanager', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page['SecretList']:
                if not secret.get('RotationEnabled', False):
                    findings.append(Finding(
                        check_id="aws-secretsmanager-002", service="SecretsManager",
                        resource_id=secret['Name'], region=region, account_id=account_id,
                        issue="Secret rotation not enabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Static secrets increase exposure window if leaked",
                        arn=secret['ARN'],
                    ))
    except Exception:
        pass

    return findings
