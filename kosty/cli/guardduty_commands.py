import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def guardduty(ctx):
    """GuardDuty operations"""
    pass

@guardduty.command('audit')
@common_options
@click.pass_context
def guardduty_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run GuardDuty complete audit"""
    execute_engine_command(ctx, 'GuardDuty', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@guardduty.command('cost-audit')
@common_options
@click.pass_context
def guardduty_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run GuardDuty cost optimization audit"""
    execute_engine_command(ctx, 'GuardDuty', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@guardduty.command('security-audit')
@common_options
@click.pass_context
def guardduty_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run GuardDuty security audit"""
    execute_engine_command(ctx, 'GuardDuty', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@guardduty.command('check-enabled')
@common_options
@click.pass_context
def guardduty_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify GuardDuty is enabled"""
    execute_engine_command(ctx, 'GuardDuty', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-guardduty-001')

