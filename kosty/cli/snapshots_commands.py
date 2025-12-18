import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def snapshots(ctx):
    """EBS Snapshots operations"""
    pass

@snapshots.command('audit')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete EBS Snapshots audit"""
    from ..services.snapshots_audit import SnapshotsAuditService
    execute_service_command(ctx, SnapshotsAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@snapshots.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS Snapshots cost optimization audit only"""
    from ..services.snapshots_audit import SnapshotsAuditService
    execute_service_command(ctx, SnapshotsAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@snapshots.command('security-audit')
@common_options
@click.pass_context
def snapshots_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS Snapshots security audit only"""
    from ..services.snapshots_audit import SnapshotsAuditService
    execute_service_command(ctx, SnapshotsAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@snapshots.command('check-old-snapshots')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_check_old(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find old EBS snapshots"""
    from ..services.snapshots_audit import SnapshotsAuditService
    execute_service_command(ctx, SnapshotsAuditService, 'check_old_snapshots', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@snapshots.command('find-old-snapshots')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_find_old(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find old EBS snapshots (alternative method)"""
    from ..services.snapshots_audit import SnapshotsAuditService
    execute_service_command(ctx, SnapshotsAuditService, 'find_old_snapshots', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)