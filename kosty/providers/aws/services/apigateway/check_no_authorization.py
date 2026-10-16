from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-003", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find endpoints with no authorization")
def check_no_authorization(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag methods where AUTH_TYPE is NONE — open to anyone."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            try:
                resources = apigw.get_resources(restApiId=api['id'])
                for res in resources.get('items', []):
                    for method_name in res.get('resourceMethods', {}):
                        try:
                            method = apigw.get_method(restApiId=api['id'], resourceId=res['id'], httpMethod=method_name)
                            if method.get('authorizationType') == 'NONE':
                                path = res.get('path', '/')
                                findings.append(Finding(
                                    check_id="aws-apigateway-003", service="APIGateway",
                                    resource_id=f"{api['name']}:{method_name} {path}",
                                    region=region, account_id=account_id,
                                    issue=f"No authorization on {method_name} {path}",
                                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                    risk="Unauthenticated access to backend",
                                ))
                        except Exception as _exc:
                            handle_check_error(_exc)
                            continue
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
