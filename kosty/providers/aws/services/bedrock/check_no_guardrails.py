from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-bedrock-003", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check if Bedrock Guardrails are configured")
def check_no_guardrails(session, region, **kwargs):
    """Flag accounts with no protection against prompt injection or PII leakage."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
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
    except Exception:
        pass
    return findings
