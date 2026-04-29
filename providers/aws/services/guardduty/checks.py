"""GuardDuty checks — native plugin format."""

from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-guardduty-001",
    service="GuardDuty",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify GuardDuty threat detection is enabled in the region",
)
def check_not_enabled(session, region, **kwargs):
    """Flag regions where GuardDuty is not active."""
    gd = session.client('guardduty', region_name=region)
    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']
    findings = []

    try:
        detectors = gd.list_detectors()['DetectorIds']

        if not detectors:
            findings.append(Finding(
                check_id="aws-guardduty-001",
                service="GuardDuty",
                resource_id="guardduty",
                region=region,
                account_id=account_id,
                issue="GuardDuty not enabled in this region",
                severity=Severity.HIGH,
                finding_type=FindingType.SECURITY,
                risk="No threat detection — compromised instances, crypto mining, and credential exfiltration go undetected",
            ))
        else:
            for detector_id in detectors:
                detector = gd.get_detector(DetectorId=detector_id)
                if detector.get('Status') != 'ENABLED':
                    findings.append(Finding(
                        check_id="aws-guardduty-001",
                        service="GuardDuty",
                        resource_id=detector_id,
                        region=region,
                        account_id=account_id,
                        issue="GuardDuty detector is disabled",
                        severity=Severity.HIGH,
                        finding_type=FindingType.SECURITY,
                        risk="Threat detection suspended",
                        resource_name=f"Detector {detector_id}",
                    ))
    except Exception:
        pass

    return findings
