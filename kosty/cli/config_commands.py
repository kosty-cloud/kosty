import click
from .utils import common_options, execute_engine_command

@click.group(name='awsconfig')
@click.pass_context
def awsconfig(ctx):
    """Config operations"""
    pass

@awsconfig.command('audit')
@common_options
@click.pass_context
def awsconfig_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Config complete audit"""
    execute_engine_command(ctx, 'Config', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@awsconfig.command('cost-audit')
@common_options
@click.pass_context
def awsconfig_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Config cost optimization audit"""
    execute_engine_command(ctx, 'Config', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@awsconfig.command('security-audit')
@common_options
@click.pass_context
def awsconfig_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Config security audit"""
    execute_engine_command(ctx, 'Config', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@awsconfig.command('check-enabled')
@common_options
@click.pass_context
def awsconfig_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify AWS Config is enabled"""
    execute_engine_command(ctx, 'Config', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-config-001')

