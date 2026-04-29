import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-apigateway-010", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find APIs behind CloudFront without resource policy restricting direct access")
def check_cloudfront_bypass(session, region, **kwargs):
    """Flag APIs reachable directly, bypassing CloudFront WAF protections."""
    apigw = session.client('apigateway', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    cf_api_origins = set()
    try:
        cf = session.client('cloudfront')
        dists = cf.list_distributions()
        if 'DistributionList' in dists and 'Items' in dists['DistributionList']:
            for dist in dists['DistributionList']['Items']:
                for origin in dist.get('Origins', {}).get('Items', []):
                    domain = origin.get('DomainName', '')
                    if '.execute-api.' in domain:
                        cf_api_origins.add(domain.split('.')[0])
    except Exception:
        return findings

    if not cf_api_origins:
        return findings

    try:
        for api in apigw.get_rest_apis().get('items', []):
            if api['id'] not in cf_api_origins:
                continue
            policy_str = api.get('policy', '')
            if not policy_str:
                findings.append(Finding(
                    check_id="aws-apigateway-010", service="APIGateway",
                    resource_id=api['name'], region=region, account_id=account_id,
                    issue="CloudFront bypass — no resource policy restricting direct access",
                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                    risk="Attackers can hit the API directly, bypassing WAF",
                ))
                continue
            try:
                policy = json.loads(policy_str.replace('\\', ''))
                has_restriction = any(
                    'aws:SourceIp' in json.dumps(s.get('Condition', {})) or
                    'aws:Referer' in json.dumps(s.get('Condition', {}))
                    for s in policy.get('Statement', [])
                )
                if not has_restriction:
                    findings.append(Finding(
                        check_id="aws-apigateway-010", service="APIGateway",
                        resource_id=api['name'], region=region, account_id=account_id,
                        issue="CloudFront bypass — resource policy does not restrict to CloudFront",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Direct bypass possible despite CloudFront in front",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
