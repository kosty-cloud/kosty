import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def apigateway(ctx):
    """APIGateway operations"""
    pass


@apigateway.command('audit')
@common_options
@click.pass_context
def apigateway_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run APIGateway complete audit"""
    execute_engine_command(ctx, 'APIGateway', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('cost-audit')
@common_options
@click.pass_context
def apigateway_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run APIGateway cost optimization audit"""
    execute_engine_command(ctx, 'APIGateway', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('security-audit')
@common_options
@click.pass_context
def apigateway_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run APIGateway security audit"""
    execute_engine_command(ctx, 'APIGateway', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@apigateway.command('check-zero-requests')
@common_options
@click.pass_context
def apigateway_check_zero_requests(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find APIs with zero requests"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-001')


@apigateway.command('check-no-waf')
@common_options
@click.pass_context
def apigateway_check_no_waf(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stages not protected by WAF"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-002')


@apigateway.command('check-no-auth')
@common_options
@click.pass_context
def apigateway_check_no_auth(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find endpoints with no authorization"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-003')


@apigateway.command('check-no-logging')
@common_options
@click.pass_context
def apigateway_check_no_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stages with logging disabled"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-004')


@apigateway.command('check-no-throttling')
@common_options
@click.pass_context
def apigateway_check_no_throttling(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stages without custom throttling"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-005')


@apigateway.command('check-no-resource-policy')
@common_options
@click.pass_context
def apigateway_check_no_resource_policy(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find private APIs without resource policy"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-006')


@apigateway.command('check-no-jwt-auth')
@common_options
@click.pass_context
def apigateway_check_no_jwt_auth(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find HTTP APIs without JWT authorizer"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-007')


@apigateway.command('check-no-tls12')
@common_options
@click.pass_context
def apigateway_check_no_tls12(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find domains not enforcing TLS 1.2"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-008')


@apigateway.command('check-no-request-validation')
@common_options
@click.pass_context
def apigateway_check_no_request_validation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find methods without request validation"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-009')


@apigateway.command('check-cloudfront-bypass')
@common_options
@click.pass_context
def apigateway_check_cloudfront_bypass(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find APIs behind CloudFront without direct access restriction"""
    execute_engine_command(ctx, 'APIGateway', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-apigateway-010')

