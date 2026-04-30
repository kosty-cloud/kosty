from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-sagemaker-007", service="SageMaker", provider="aws", finding_type=FindingType.SECURITY, description="Find notebooks with root access enabled")
def check_notebook_root_access(session, region, **kwargs):
    """Flag notebooks where users have root inside the container."""
    sm = session.client('sagemaker', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for nb in sm.list_notebook_instances().get('NotebookInstances', []):
            try:
                detail = sm.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
                if detail.get('RootAccess') == 'Enabled':
                    findings.append(Finding(
                        check_id="aws-sagemaker-007", service="SageMaker",
                        resource_id=nb['NotebookInstanceName'], region=region, account_id=account_id,
                        issue="Root access enabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Container escape risk — root can compromise the host",
                        arn=nb.get('NotebookInstanceArn', ''),
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
