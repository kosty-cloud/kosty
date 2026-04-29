import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-bedrock-010", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check training data S3 buckets for cross-account access")
def check_cross_account_model_access(session, region, **kwargs):
    """Flag custom model training data accessible by external accounts."""
    bedrock = session.client('bedrock', region_name=region)
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        checked = set()
        for model in bedrock.list_custom_models().get('modelSummaries', []):
            try:
                detail = bedrock.get_custom_model(modelIdentifier=model['modelName'])
                uri = detail.get('trainingDataConfig', {}).get('s3Uri', '')
                if not uri or not uri.startswith('s3://'):
                    continue
                bucket = uri.split('/')[2]
                if bucket in checked:
                    continue
                checked.add(bucket)
                try:
                    policy = json.loads(s3.get_bucket_policy(Bucket=bucket)['Policy'])
                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') != 'Allow':
                            continue
                        principal = stmt.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            findings.append(Finding(
                                check_id="aws-bedrock-010", service="Bedrock",
                                resource_id=bucket, region=region, account_id=account_id,
                                issue=f"Training data bucket has wildcard principal",
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="Unauthorized access to model training data",
                            ))
                            break
                except Exception:
                    pass
            except Exception:
                continue
    except Exception:
        pass
    return findings
