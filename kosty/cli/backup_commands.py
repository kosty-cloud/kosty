import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def backup(ctx):
    """AWS Backup operations"""
    pass

@backup.command('audit')
@common_options
@click.pass_context
def backup_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete AWS Backup audit"""
    from ..services.backup_audit import BackupAuditService
    execute_service_command(ctx, BackupAuditService, 'audit', output, organization, region, max_workers, regions)

@backup.command('cost-audit')
@common_options
@click.pass_context
def backup_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run AWS Backup cost optimization audit only"""
    from ..services.backup_audit import BackupAuditService
    execute_service_command(ctx, BackupAuditService, 'cost_audit', output, organization, region, max_workers, regions)

@backup.command('security-audit')
@common_options
@click.pass_context
def backup_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run AWS Backup security audit only"""
    from ..services.backup_audit import BackupAuditService
    execute_service_command(ctx, BackupAuditService, 'security_audit', output, organization, region, max_workers, regions)

@backup.command('check-empty-vaults')
@common_options
@click.pass_context
def backup_check_empty(ctx, organization, region, max_workers, regions, output):
    """Find empty backup vaults"""
    from ..services.backup_audit import BackupAuditService
    execute_service_command(ctx, BackupAuditService, 'check_empty_backup_vaults', output, organization, region, max_workers, regions)

@backup.command('check-cross-region-backup')
@common_options
@click.pass_context
def backup_check_cross_region(ctx, organization, region, max_workers, regions, output):
    """Find cross-region backup for dev/test"""
    from ..services.backup_audit import BackupAuditService
    execute_service_command(ctx, BackupAuditService, 'check_cross_region_backup_dev_test', output, organization, region, max_workers, regions)