import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def acm(ctx):
    """ACM (Certificate Manager) operations"""
    pass


@acm.command('audit')
@click.option('--days', default=30, type=int, help='Days before expiration to flag (default: 30)')
@common_options
@click.pass_context
def acm_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ACM audit"""
    from ..services.acm_audit import ACMAuditService
    execute_service_command(ctx, ACMAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@acm.command('check-expiring-certificates')
@click.option('--days', default=30, type=int, help='Days before expiration to flag (default: 30)')
@common_options
@click.pass_context
def acm_check_expiring(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find certificates expiring soon"""
    from ..services.acm_audit import ACMAuditService
    execute_service_command(ctx, ACMAuditService, 'check_expiring_certificates', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)
