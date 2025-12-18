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