from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-lb-001", service="LB", provider="aws", finding_type=FindingType.COST, description="Find load balancers with no healthy targets")
def check_no_healthy_targets(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag ALBs/NLBs routing to nothing — pure waste."""
    elb = session.client('elbv2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for lb in elb.describe_load_balancers()['LoadBalancers']:
            try:
                tgs = elb.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                has_healthy = False
                for tg in tgs['TargetGroups']:
                    health = elb.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                    if any(t['TargetHealth']['State'] == 'healthy' for t in health['TargetHealthDescriptions']):
                        has_healthy = True
                        break
                if not has_healthy:
                    findings.append(Finding(
                        check_id="aws-lb-001", service="LB",
                        resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                        issue="No healthy targets",
                        severity=Severity.HIGH, finding_type=FindingType.COST,
                        risk="$16.43/mo per ALB with no traffic served",
                        arn=lb['LoadBalancerArn'], monthly_savings=16.43,
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-lb-002", service="LB", provider="aws", finding_type=FindingType.SECURITY, description="Find HTTP listeners without HTTPS redirect")
def check_http_without_redirect(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag listeners accepting plaintext HTTP without forcing TLS."""
    elb = session.client('elbv2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for lb in elb.describe_load_balancers()['LoadBalancers']:
            try:
                listeners = elb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                for listener in listeners['Listeners']:
                    if listener.get('Protocol') == 'HTTP':
                        actions = listener.get('DefaultActions', [])
                        has_redirect = any(a.get('Type') == 'redirect' and a.get('RedirectConfig', {}).get('Protocol') == 'HTTPS' for a in actions)
                        if not has_redirect:
                            findings.append(Finding(
                                check_id="aws-lb-002", service="LB",
                                resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                                issue="HTTP listener without HTTPS redirect",
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="Traffic in plaintext — credentials and data exposed",
                                arn=lb['LoadBalancerArn'],
                            ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
