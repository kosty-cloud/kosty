from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-003", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check if Bedrock Guardrails are configured")
def check_no_guardrails(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts with no protection against prompt injection or PII leakage."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        if not bedrock.list_guardrails().get('guardrails', []):
            findings.append(Finding(
                check_id="aws-bedrock-003", service="Bedrock",
                resource_id="bedrock-guardrails", region=region, account_id=account_id,
                issue="No Bedrock Guardrails configured",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="No protection against prompt injection or PII leakage in responses",
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
