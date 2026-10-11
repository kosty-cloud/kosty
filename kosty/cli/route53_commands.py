import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def route53(ctx):
    """Route53 operations"""
    pass

@route53.command('audit')
@common_options
@click.pass_context
def route53_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Route53 complete audit"""
    execute_engine_command(ctx, 'Route53', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('cost-audit')
@common_options
@click.pass_context
def route53_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Route53 cost optimization audit"""
    execute_engine_command(ctx, 'Route53', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('security-audit')
@common_options
@click.pass_context
def route53_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Route53 security audit"""
    execute_engine_command(ctx, 'Route53', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('check-empty-zones')
@common_options
@click.pass_context
def route53_check_empty_zones(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find hosted zones with no records"""
    execute_engine_command(ctx, 'Route53', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-route53-001')

