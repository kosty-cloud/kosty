from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-acm-001",
    service="ACM",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find certificates expiring within 30 days",
)
def check_expiring_certificates(session, region, days=30, **kwargs):
    """Flag ACM certificates approaching expiration."""
    acm = session.client('acm', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        paginator = acm.get_paginator('list_certificates')
        cutoff = datetime.now() + timedelta(days=days)

        for page in paginator.paginate(CertificateStatuses=['ISSUED']):
            for cert in page['CertificateSummaryList']:
                not_after = cert.get('NotAfter')
                if not not_after:
                    continue
                if not_after.replace(tzinfo=None) < cutoff:
                    days_left = (not_after.replace(tzinfo=None) - datetime.now()).days
                    sev = Severity.CRITICAL if days_left < 7 else Severity.HIGH if days_left < 14 else Severity.MEDIUM
                    findings.append(Finding(
                        check_id="aws-acm-001", service="ACM",
                        resource_id=cert['DomainName'], region=region, account_id=account_id,
                        issue=f"Certificate expires in {days_left} days",
                        severity=sev, finding_type=FindingType.SECURITY,
                        risk="Service outage when certificate expires",
                        arn=cert['CertificateArn'],
                    ))
    except Exception:
        pass

    return findings
