import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def kms(ctx):
    """KMS operations"""
    pass


@kms.command('audit')
@common_options
@click.pass_context
def kms_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run KMS complete audit"""
    execute_engine_command(ctx, 'KMS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@kms.command('cost-audit')
@common_options
@click.pass_context
def kms_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run KMS cost optimization audit"""
    execute_engine_command(ctx, 'KMS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@kms.command('security-audit')
@common_options
@click.pass_context
def kms_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run KMS security audit"""
    execute_engine_command(ctx, 'KMS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@kms.command('check-no-rotation')
@common_options
@click.pass_context
def kms_check_no_rotation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find keys without automatic rotation"""
    execute_engine_command(ctx, 'KMS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-kms-001')

