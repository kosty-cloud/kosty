from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-sagemaker-008", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find GPU endpoints not using Inference Components")
def check_no_inference_components(session, region, **kwargs):
    """Flag endpoints wasting GPU capacity — IC allows multi-model packing."""
    sm = session.client('sagemaker', region_name=region)
    account_id = get_account_id(session)
    findings = []
    gpu_families = ['ml.g4', 'ml.g5', 'ml.p3', 'ml.p4', 'ml.p5', 'ml.inf']
    try:
        for ep in sm.list_endpoints(StatusEquals='InService').get('Endpoints', []):
            try:
                detail = sm.describe_endpoint(EndpointName=ep['EndpointName'])
                for variant in detail.get('ProductionVariants', []):
                    itype = variant.get('CurrentInstanceType', '')
                    if not any(itype.startswith(f) for f in gpu_families):
                        continue
                    ics = sm.list_inference_components(EndpointNameEquals=ep['EndpointName'])
                    if not ics.get('InferenceComponents', []):
                        findings.append(Finding(
                            check_id="aws-sagemaker-008", service="SageMaker",
                            resource_id=ep['EndpointName'], region=region, account_id=account_id,
                            issue=f"GPU endpoint ({itype}) without Inference Components",
                            severity=Severity.MEDIUM, finding_type=FindingType.COST,
                            risk="Up to 80% savings by packing multiple models per GPU",
                            arn=ep.get('EndpointArn', ''),
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
