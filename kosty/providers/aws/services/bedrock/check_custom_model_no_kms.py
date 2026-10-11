from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-bedrock-006", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check if custom models are encrypted with customer-managed KMS")
def check_custom_model_no_kms(session, region, **kwargs):
    """Flag custom models relying on AWS-managed encryption only."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for model in bedrock.list_custom_models().get('modelSummaries', []):
            try:
                detail = bedrock.get_custom_model(modelIdentifier=model['modelName'])
                if not detail.get('customModelKmsKeyId', ''):
                    findings.append(Finding(
                        check_id="aws-bedrock-006", service="Bedrock",
                        resource_id=model['modelName'], region=region, account_id=account_id,
                        issue="Custom model not encrypted with customer-managed KMS",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Less control over key lifecycle", arn=model.get('modelArn', ''),
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
