from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-008", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find custom domains not enforcing TLS 1.2")
def check_custom_domain_no_tls12(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag domains accepting connections with weak TLS versions."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for domain in apigw.get_domain_names().get('items', []):
            policy = domain.get('securityPolicy', '')
            if policy != 'TLS_1_2':
                findings.append(Finding(
                    check_id="aws-apigateway-008", service="APIGateway",
                    resource_id=domain['domainName'], region=region, account_id=account_id,
                    issue=f"Custom domain using {policy or 'default'} instead of TLS 1.2",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="Vulnerable to downgrade attacks",
                ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
