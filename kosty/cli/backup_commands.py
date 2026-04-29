import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def backup(ctx):
    """Backup operations"""
    pass


@backup.command('audit')
@common_options
@click.pass_context
def backup_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Backup complete audit"""
    execute_engine_command(ctx, 'Backup', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@backup.command('cost-audit')
@common_options
@click.pass_context
def backup_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Backup cost optimization audit"""
    execute_engine_command(ctx, 'Backup', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@backup.command('security-audit')
@common_options
@click.pass_context
def backup_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Backup security audit"""
    execute_engine_command(ctx, 'Backup', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@backup.command('check-empty-vaults')
@common_options
@click.pass_context
def backup_check_empty_vaults(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find empty AWS Backup vaults"""
    execute_engine_command(ctx, 'Backup', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-backup-001')


@backup.command('check-cross-region-dev')
@common_options
@click.pass_context
def backup_check_cross_region_dev(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find cross-region backup for dev/test"""
    execute_engine_command(ctx, 'Backup', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-backup-002')

