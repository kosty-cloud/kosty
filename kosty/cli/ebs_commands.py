import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def ebs(ctx):
    """EBS operations"""
    pass


@ebs.command('audit')
@common_options
@click.pass_context
def ebs_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS complete audit"""
    execute_engine_command(ctx, 'EBS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@ebs.command('cost-audit')
@common_options
@click.pass_context
def ebs_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS cost optimization audit"""
    execute_engine_command(ctx, 'EBS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@ebs.command('security-audit')
@common_options
@click.pass_context
def ebs_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EBS security audit"""
    execute_engine_command(ctx, 'EBS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@ebs.command('check-detached')
@common_options
@click.pass_context
def ebs_check_detached(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find detached EBS volumes"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-001')


@ebs.command('check-gp2')
@common_options
@click.pass_context
def ebs_check_gp2(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find gp2 volumes (should be gp3)"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-002')


@ebs.command('check-unencrypted-detached')
@common_options
@click.pass_context
def ebs_check_unencrypted_detached(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unencrypted detached volumes"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-003')


@ebs.command('check-unencrypted')
@common_options
@click.pass_context
def ebs_check_unencrypted(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unencrypted volumes in use"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-004')


@ebs.command('check-public-snapshots')
@common_options
@click.pass_context
def ebs_check_public_snapshots(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find public EBS snapshots"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-005')


@ebs.command('check-no-snapshot')
@common_options
@click.pass_context
def ebs_check_no_snapshot(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find volumes with no recent snapshot"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-006')


@ebs.command('check-low-io')
@common_options
@click.pass_context
def ebs_check_low_io(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find volumes with very low I/O"""
    execute_engine_command(ctx, 'EBS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ebs-007')

