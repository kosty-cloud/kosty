import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def s3(ctx):
    """S3 operations"""
    pass

@s3.command('audit')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete S3 audit (cost + security)"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@s3.command('cost-audit')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run S3 cost optimization audit only"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@s3.command('security-audit')
@common_options
@click.pass_context
def s3_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run S3 security audit only"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-empty-buckets')
@common_options
@click.pass_context
def s3_check_empty(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find empty S3 buckets"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_empty_buckets', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-incomplete-uploads')
@click.option('--days', default=7, help='Days threshold for incomplete uploads')
@common_options
@click.pass_context
def s3_check_incomplete_uploads(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find incomplete multipart uploads"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_incomplete_uploads', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@s3.command('check-lifecycle-policy')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_check_lifecycle_policy(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets needing lifecycle policies"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_lifecycle_policy', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@s3.command('check-public-read-access')
@common_options
@click.pass_context
def s3_check_public_read(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with public read access"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_public_read_access', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-public-write-access')
@common_options
@click.pass_context
def s3_check_public_write(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with public write access"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_public_write_access', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-encryption-at-rest')
@common_options
@click.pass_context
def s3_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without encryption"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_encryption_at_rest', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-versioning-disabled')
@common_options
@click.pass_context
def s3_check_versioning(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without versioning"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_versioning_disabled', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-access-logging')
@common_options
@click.pass_context
def s3_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without access logging"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_access_logging', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-bucket-policy-wildcards')
@common_options
@click.pass_context
def s3_check_wildcards(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets with wildcard policies"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_bucket_policy_wildcards', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@s3.command('check-mfa-delete')
@common_options
@click.pass_context
def s3_check_mfa_delete(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find buckets without MFA delete"""
    from ..services.s3_audit import S3AuditService
    execute_service_command(ctx, S3AuditService, 'check_mfa_delete', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)