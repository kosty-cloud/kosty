import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def ssm(ctx):
    """SSM (Systems Manager) operations"""
    pass


@ssm.command('audit')
@common_options
@click.pass_context
def ssm_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SSM audit"""
    from ..services.ssm_audit import SSMAuditService
    execute_service_command(ctx, SSMAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@ssm.command('check-non-compliant-patches')
@common_options
@click.pass_context
def ssm_check_patches(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with missing security patches"""
    from ..services.ssm_audit import SSMAuditService
    execute_service_command(ctx, SSMAuditService, 'check_non_compliant_patches', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
