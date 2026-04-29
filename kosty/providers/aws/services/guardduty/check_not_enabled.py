from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-guardduty-001",
    service="GuardDuty",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify GuardDuty threat detection is enabled",
)
def check_not_enabled(session, region, **kwargs):
    """Flag regions where GuardDuty is not active."""
    gd = session.client('guardduty', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        detectors = gd.list_detectors()['DetectorIds']
        if not detectors:
            findings.append(Finding(
                check_id="aws-guardduty-001", service="GuardDuty",
                resource_id="guardduty", region=region, account_id=account_id,
                issue="GuardDuty not enabled in this region",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="No threat detection — compromised instances and credential exfiltration go undetected",
            ))
        else:
            for did in detectors:
                det = gd.get_detector(DetectorId=did)
                if det.get('Status') != 'ENABLED':
                    findings.append(Finding(
                        check_id="aws-guardduty-001", service="GuardDuty",
                        resource_id=did, region=region, account_id=account_id,
                        issue="GuardDuty detector is disabled",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Threat detection suspended",
                    ))
    except Exception:
        pass

    return findings
