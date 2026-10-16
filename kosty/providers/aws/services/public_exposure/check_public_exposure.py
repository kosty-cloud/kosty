from typing import List

from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-exposure-001",
    service="PublicExposure",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Map external attack surface across 15 resource types",
)
def check_public_exposure(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Scan all publicly exposed resources and classify protection level."""
    from kosty.providers.aws.services.public_exposure.service import PublicExposureService

    svc = PublicExposureService()
    raw_results = svc.audit(session, region, **kwargs)

    findings = []
    severity_map = {'critical': Severity.CRITICAL, 'high': Severity.HIGH, 'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO}

    for item in raw_results:
        findings.append(Finding(
            check_id="aws-exposure-001",
            service="PublicExposure",
            resource_id=item.get('ResourceId', ''),
            region=item.get('Region', region),
            account_id=item.get('AccountId', ''),
            issue=item.get('Issue', ''),
            severity=severity_map.get(item.get('severity', 'high'), Severity.HIGH),
            finding_type=FindingType.SECURITY,
            risk=item.get('Risk', ''),
            details=item.get('Details', {}),
        ))
    return findings
