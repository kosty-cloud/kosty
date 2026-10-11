import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def s3(ctx):
    """S3 operations"""
    pass

@s3.command('audit')
@common_options
@click.pass_context
def s3_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete S3 audit (cost + security)"""
    execute_engine_command(ctx, 'S3', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('cost-audit')
@common_options
@click.pass_context
def s3_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run S3 cost optimization audit only"""
    execute_engine_command(ctx, 'S3', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('security-audit')
@common_options
@click.pass_context
def s3_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run S3 security audit only"""
    execute_engine_command(ctx, 'S3', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-empty-buckets')
@common_options
@click.pass_context
def s3_check_empty(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find empty S3 buckets"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-001')

@s3.command('check-incomplete-uploads')
@common_options
@click.pass_context
def s3_check_uploads(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find incomplete multipart uploads"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-002')

@s3.command('check-no-lifecycle')
@common_options
@click.pass_context
def s3_check_lifecycle(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without lifecycle policy"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-003')

@s3.command('check-public-read')
@common_options
@click.pass_context
def s3_check_public_read(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with public read access"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-004')

@s3.command('check-public-write')
@common_options
@click.pass_context
def s3_check_public_write(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with public write access"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-005')

@s3.command('check-no-encryption')
@common_options
@click.pass_context
def s3_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without encryption"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-006')

@s3.command('check-no-versioning')
@common_options
@click.pass_context
def s3_check_versioning(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without versioning"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-007')

@s3.command('check-no-logging')
@common_options
@click.pass_context
def s3_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without access logging"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-008')

@s3.command('check-wildcard-principal')
@common_options
@click.pass_context
def s3_check_wildcard(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with wildcard principal in policy"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-009')

@s3.command('check-no-mfa-delete')
@common_options
@click.pass_context
def s3_check_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without MFA delete"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-010')

@s3.command('check-no-object-lock')
@common_options
@click.pass_context
def s3_check_object_lock(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without Object Lock"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-011')

@s3.command('check-no-replication')
@common_options
@click.pass_context
def s3_check_replication(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without cross-region replication"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-012')

@s3.command('check-account-public-access')
@common_options
@click.pass_context
def s3_check_account_public(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check account-level S3 Block Public Access"""
    execute_engine_command(ctx, 'S3', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-s3-013')
