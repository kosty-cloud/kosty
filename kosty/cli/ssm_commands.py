import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def ssm(ctx):
    """SSM operations"""
    pass

@ssm.command('audit')
@common_options
@click.pass_context
def ssm_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SSM complete audit"""
    execute_engine_command(ctx, 'SSM', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ssm.command('cost-audit')
@common_options
@click.pass_context
def ssm_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SSM cost optimization audit"""
    execute_engine_command(ctx, 'SSM', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ssm.command('security-audit')
@common_options
@click.pass_context
def ssm_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SSM security audit"""
    execute_engine_command(ctx, 'SSM', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ssm.command('check-missing-patches')
@common_options
@click.pass_context
def ssm_check_missing_patches(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with missing patches"""
    execute_engine_command(ctx, 'SSM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ssm-001')

