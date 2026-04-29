import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def acm(ctx):
    """ACM operations"""
    pass


@acm.command('audit')
@common_options
@click.pass_context
def acm_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ACM complete audit"""
    execute_engine_command(ctx, 'ACM', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@acm.command('cost-audit')
@common_options
@click.pass_context
def acm_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ACM cost optimization audit"""
    execute_engine_command(ctx, 'ACM', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@acm.command('security-audit')
@common_options
@click.pass_context
def acm_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ACM security audit"""
    execute_engine_command(ctx, 'ACM', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@acm.command('check-expiring')
@common_options
@click.pass_context
def acm_check_expiring(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find certificates expiring within 30 days"""
    execute_engine_command(ctx, 'ACM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-acm-001')

