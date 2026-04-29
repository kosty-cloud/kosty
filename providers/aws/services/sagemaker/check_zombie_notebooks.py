from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-sagemaker-002", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find running notebook instances")
def check_zombie_notebooks(session, region, **kwargs):
    """Flag notebooks in InService state — billed even when idle."""
    sm = session.client('sagemaker', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for nb in sm.list_notebook_instances(StatusEquals='InService').get('NotebookInstances', []):
            findings.append(Finding(
                check_id="aws-sagemaker-002", service="SageMaker",
                resource_id=nb['NotebookInstanceName'], region=region, account_id=account_id,
                issue=f"Running notebook ({nb.get('InstanceType', 'unknown')})",
                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                risk="~$48/mo per ml.t3.medium — billed even when idle",
                arn=nb.get('NotebookInstanceArn', ''),
            ))
    except Exception:
        pass
    return findings
