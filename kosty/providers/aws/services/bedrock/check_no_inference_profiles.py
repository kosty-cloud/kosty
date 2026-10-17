from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-008", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Check if Application Inference Profiles are configured")
def check_no_inference_profiles(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag accounts with no cost attribution mechanism for GenAI spend."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        profiles = bedrock.list_inference_profiles()
        if not profiles.get('inferenceProfileSummaries', []):
            findings.append(Finding(
                check_id="aws-bedrock-008", service="Bedrock",
                resource_id="inference-profiles", region=region, account_id=account_id,
                issue="No Application Inference Profiles configured",
                severity=Severity.LOW, finding_type=FindingType.COST,
                risk="Cannot attribute token spend per team or project",
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
