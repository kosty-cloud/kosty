import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def ebs(ctx):
    """EBS volume operations"""
    pass

@ebs.command('audit')
@click.option('--days', default=7, help='Days threshold for I/O analysis and snapshots')
@common_options
@click.pass_context
def ebs_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete EBS audit (cost + security)"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@ebs.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for I/O analysis')
@common_options
@click.pass_context
def ebs_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS cost optimization audit only"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@ebs.command('security-audit')
@common_options
@click.pass_context
def ebs_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS security audit only"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

# Cost optimization checks
@ebs.command('check-orphan-volumes')
@common_options
@click.pass_context
def ebs_check_orphan(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find orphaned EBS volumes"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_orphan_volumes', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ebs.command('check-low-io-volumes')
@click.option('--iops-threshold', default=10, help='IOPS per GB threshold')
@click.option('--days', default=7, help='Days to analyze I/O')
@common_options
@click.pass_context
def ebs_check_low_io(ctx, iops_threshold, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find volumes with low I/O"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_low_io_volumes', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, iops_threshold=iops_threshold, days=days)

@ebs.command('check-old-snapshots')
@click.option('--days', default=90, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def ebs_check_old_snapshots(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find old EBS snapshots"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_old_snapshots', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@ebs.command('check-gp2-volumes')
@common_options
@click.pass_context
def ebs_check_gp2(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find gp2 volumes (should be gp3)"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_gp2_volumes', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

# Security checks
@ebs.command('check-unencrypted-orphan')
@common_options
@click.pass_context
def ebs_check_unencrypted_orphan(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unencrypted orphaned volumes"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_unencrypted_orphan', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ebs.command('check-unencrypted-in-use')
@common_options
@click.pass_context
def ebs_check_unencrypted_in_use(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unencrypted volumes in use"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_unencrypted_in_use', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ebs.command('check-public-snapshots')
@common_options
@click.pass_context
def ebs_check_public_snapshots(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find public snapshots"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_public_snapshots', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ebs.command('check-no-recent-snapshot')
@click.option('--days', default=7, help='Days threshold for recent snapshots')
@common_options
@click.pass_context
def ebs_check_no_recent_snapshot(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find volumes with no recent snapshots"""
    from ..services.ebs_audit import EBSAuditService
    execute_service_command(ctx, EBSAuditService, 'check_no_recent_snapshot', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)