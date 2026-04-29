from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-secretsmanager-001",
    service="SecretsManager",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find secrets never accessed but billed $0.40/mo",
)
def check_unused_secrets(session, region, days=90, **kwargs):
    """Flag secrets that haven't been retrieved in 90+ days."""
    sm = session.client('secretsmanager', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        cutoff = datetime.now() - timedelta(days=days)
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page['SecretList']:
                last = secret.get('LastAccessedDate')
                if not last or last.replace(tzinfo=None) < cutoff:
                    findings.append(Finding(
                        check_id="aws-secretsmanager-001", service="SecretsManager",
                        resource_id=secret['Name'], region=region, account_id=account_id,
                        issue=f"Secret unused for {days}+ days ($0.40/mo)",
                        severity=Severity.LOW, finding_type=FindingType.COST,
                        risk="Waste $0.40/mo per unused secret",
                        arn=secret['ARN'], monthly_savings=0.40,
                    ))
    except Exception:
        pass

    return findings
