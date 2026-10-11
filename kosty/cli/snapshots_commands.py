import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def snapshots(ctx):
    """Snapshots operations"""
    pass

@snapshots.command('audit')
@common_options
@click.pass_context
def snapshots_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Snapshots complete audit"""
    execute_engine_command(ctx, 'Snapshots', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@snapshots.command('cost-audit')
@common_options
@click.pass_context
def snapshots_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Snapshots cost optimization audit"""
    execute_engine_command(ctx, 'Snapshots', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@snapshots.command('security-audit')
@common_options
@click.pass_context
def snapshots_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Snapshots security audit"""
    execute_engine_command(ctx, 'Snapshots', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@snapshots.command('check-old-snapshots')
@click.option('--days', default=90, help='Days threshold')
@common_options
@click.pass_context
def snapshots_check_old_snapshots(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find EBS snapshots older than 90 days"""
    execute_engine_command(ctx, 'Snapshots', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-snapshots-001', days=days)

