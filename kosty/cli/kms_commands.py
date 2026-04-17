import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def kms(ctx):
    """KMS operations"""
    pass


@kms.command('audit')
@common_options
@click.pass_context
def kms_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run KMS audit"""
    from ..services.kms_audit import KMSAuditService
    execute_service_command(ctx, KMSAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@kms.command('check-no-key-rotation')
@common_options
@click.pass_context
def kms_check_rotation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find customer-managed keys without automatic rotation"""
    from ..services.kms_audit import KMSAuditService
    execute_service_command(ctx, KMSAuditService, 'check_no_key_rotation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
