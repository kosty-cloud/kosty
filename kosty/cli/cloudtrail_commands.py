import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def cloudtrail(ctx):
    """CloudTrail operations"""
    pass


@cloudtrail.command('audit')
@common_options
@click.pass_context
def cloudtrail_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete CloudTrail audit"""
    from ..services.cloudtrail_audit import CloudTrailAuditService
    execute_service_command(ctx, CloudTrailAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@cloudtrail.command('security-audit')
@common_options
@click.pass_context
def cloudtrail_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudTrail security audit"""
    from ..services.cloudtrail_audit import CloudTrailAuditService
    execute_service_command(ctx, CloudTrailAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@cloudtrail.command('check-not-enabled')
@common_options
@click.pass_context
def cloudtrail_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if CloudTrail is enabled with multi-region coverage"""
    from ..services.cloudtrail_audit import CloudTrailAuditService
    execute_service_command(ctx, CloudTrailAuditService, 'check_not_enabled', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@cloudtrail.command('check-no-log-validation')
@common_options
@click.pass_context
def cloudtrail_check_validation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if log file validation is enabled"""
    from ..services.cloudtrail_audit import CloudTrailAuditService
    execute_service_command(ctx, CloudTrailAuditService, 'check_no_log_validation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@cloudtrail.command('check-no-encryption')
@common_options
@click.pass_context
def cloudtrail_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if CloudTrail logs are encrypted with KMS"""
    from ..services.cloudtrail_audit import CloudTrailAuditService
    execute_service_command(ctx, CloudTrailAuditService, 'check_no_encryption', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
