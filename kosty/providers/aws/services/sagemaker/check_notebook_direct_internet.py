from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-sagemaker-006", service="SageMaker", provider="aws", finding_type=FindingType.SECURITY, description="Find notebooks with direct internet access")
def check_notebook_direct_internet(session, region, **kwargs):
    """Flag notebooks that can reach any external endpoint — data exfiltration path."""
    sm = session.client('sagemaker', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for nb in sm.list_notebook_instances().get('NotebookInstances', []):
            try:
                detail = sm.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
                if detail.get('DirectInternetAccess') == 'Enabled':
                    findings.append(Finding(
                        check_id="aws-sagemaker-006", service="SageMaker",
                        resource_id=nb['NotebookInstanceName'], region=region, account_id=account_id,
                        issue="Direct internet access enabled",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Data exfiltration path — notebook can reach any endpoint",
                        arn=nb.get('NotebookInstanceArn', ''),
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
