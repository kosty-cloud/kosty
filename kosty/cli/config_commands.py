import click
from .utils import common_options, execute_service_command


@click.group(name='config')
@click.pass_context
def awsconfig(ctx):
    """AWS Config operations"""
    pass


@awsconfig.command('audit')
@common_options
@click.pass_context
def config_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AWS Config audit"""
    from ..services.config_audit import ConfigAuditService
    execute_service_command(ctx, ConfigAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@awsconfig.command('check-not-enabled')
@common_options
@click.pass_context
def config_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if AWS Config is enabled and recording"""
    from ..services.config_audit import ConfigAuditService
    execute_service_command(ctx, ConfigAuditService, 'check_not_enabled', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
