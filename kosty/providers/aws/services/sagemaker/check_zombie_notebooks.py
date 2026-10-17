from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-sagemaker-002", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find running notebook instances")
def check_zombie_notebooks(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag notebooks in InService state — billed even when idle."""
    sm = session.client('sagemaker', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
