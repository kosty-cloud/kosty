from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-config-001",
    service="Config",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Verify AWS Config is enabled and recording",
)
def check_not_enabled(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag regions where AWS Config is not active."""
    config = session.client('config', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
