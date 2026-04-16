import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def apigateway(ctx):
    """API Gateway operations"""
    pass


@apigateway.command('audit')
@click.option('--days', default=30, help='Days threshold for unused APIs')
@common_options
@click.pass_context
def apigateway_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete API Gateway audit"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@apigateway.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused APIs')
@common_options
@click.pass_context
def apigateway_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run API Gateway cost optimization audit only"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@apigateway.command('security-audit')
@common_options
@click.pass_context
def apigateway_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run API Gateway security audit only"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-unused-apis')
@click.option('--days', default=30, help='Days threshold for API usage')
@common_options
@click.pass_context
def apigateway_check_unused(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused API Gateway APIs"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_unused_apis', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@apigateway.command('check-no-waf')
@common_options
@click.pass_context
def apigateway_check_no_waf(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find API stages not protected by WAF"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_no_waf_association', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-no-authorization')
@common_options
@click.pass_context
def apigateway_check_no_auth(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find endpoints with no authorization"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_no_authorization', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-no-logging')
@common_options
@click.pass_context
def apigateway_check_no_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stages with access/execution logging disabled"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_no_access_logging', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-no-throttling')
@common_options
@click.pass_context
def apigateway_check_no_throttling(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stages without custom throttling (cost-bleeding risk)"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_no_throttling', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-private-api-no-policy')
@common_options
@click.pass_context
def apigateway_check_private_policy(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find private APIs without a resource policy"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_private_api_no_policy', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-http-api-no-jwt')
@common_options
@click.pass_context
def apigateway_check_http_jwt(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find HTTP APIs without JWT authorizer"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_http_api_no_jwt', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-custom-domain-no-tls12')
@common_options
@click.pass_context
def apigateway_check_tls(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find custom domains not enforcing TLS 1.2"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_custom_domain_no_tls12', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-missing-request-validation')
@common_options
@click.pass_context
def apigateway_check_validation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find methods without request validation"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_missing_request_validation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-cloudfront-bypass')
@common_options
@click.pass_context
def apigateway_check_cf_bypass(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find APIs behind CloudFront without resource policy restricting direct access"""
    from ..services.apigateway_audit import APIGatewayAuditService
    execute_service_command(ctx, APIGatewayAuditService, 'check_cloudfront_bypass', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
