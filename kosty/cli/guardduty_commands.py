import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def guardduty(ctx):
    """GuardDuty operations"""
    pass


@guardduty.command('audit')
@common_options
@click.pass_context
def guardduty_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run GuardDuty audit"""
    from ..services.guardduty_audit import GuardDutyAuditService
    execute_service_command(ctx, GuardDutyAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@guardduty.command('check-not-enabled')
@common_options
@click.pass_context
def guardduty_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if GuardDuty is enabled"""
    from ..services.guardduty_audit import GuardDutyAuditService
    execute_service_command(ctx, GuardDutyAuditService, 'check_not_enabled', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
