from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-ssm-001",
    service="SSM",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find instances with missing security patches",
)
def check_non_compliant_patches(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances with failed or missing patch installations."""
    ssm = session.client('ssm', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        paginator = ssm.get_paginator('describe_instance_patch_states')
        for page in paginator.paginate():
            for inst in page['InstancePatchStates']:
                missing = inst.get('MissingCount', 0)
                failed = inst.get('FailedCount', 0)
                security = inst.get('SecurityNonCompliantCount', 0)
                if missing > 0 or failed > 0 or security > 0:
                    sev = Severity.CRITICAL if security > 0 else Severity.HIGH if missing > 5 else Severity.MEDIUM
                    findings.append(Finding(
                        check_id="aws-ssm-001", service="SSM",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"{missing} missing, {failed} failed, {security} security-critical patches",
                        severity=sev, finding_type=FindingType.SECURITY,
                        risk="Unpatched vulnerabilities exploitable by known CVEs",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
