from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-config-001",
    service="Config",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify AWS Config is enabled and recording",
)
def check_not_enabled(session, region, **kwargs):
    """Flag regions where AWS Config is not active."""
    config = session.client('config', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
        status_list = config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']

        if not recorders:
            findings.append(Finding(
                check_id="aws-config-001", service="Config",
                resource_id="aws-config", region=region, account_id=account_id,
                issue="AWS Config not configured in this region",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="No configuration change tracking — drift goes undetected",
            ))
        else:
            for status in status_list:
                if not status.get('recording', False):
                    findings.append(Finding(
                        check_id="aws-config-001", service="Config",
                        resource_id=status['name'], region=region, account_id=account_id,
                        issue="AWS Config recorder is not recording",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Configuration changes are not being tracked",
                    ))
    except Exception:
        pass

    return findings
