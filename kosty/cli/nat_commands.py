import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def nat(ctx):
    """NAT Gateway operations"""
    pass

@nat.command('audit')
@click.option('--days', default=7, help='Days threshold for data transfer analysis')
@common_options
@click.pass_context
def nat_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete NAT Gateway audit"""
    from ..services.nat_audit import NATAuditService
    execute_service_command(ctx, NATAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@nat.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for data transfer analysis')
@common_options
@click.pass_context
def nat_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run NAT Gateway cost optimization audit only"""
    from ..services.nat_audit import NATAuditService
    execute_service_command(ctx, NATAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@nat.command('security-audit')
@common_options
@click.pass_context
def nat_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run NAT Gateway security audit only"""
    from ..services.nat_audit import NATAuditService
    execute_service_command(ctx, NATAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@nat.command('check-unused-gateways')
@click.option('--days', default=7, help='Days threshold for usage analysis')
@common_options
@click.pass_context
def nat_check_unused(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused NAT Gateways"""
    from ..services.nat_audit import NATAuditService
    execute_service_command(ctx, NATAuditService, 'check_unused_nat_gateways', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@nat.command('check-redundant-gateways')
@common_options
@click.pass_context
def nat_check_redundant(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find redundant NAT Gateways"""
    from ..services.nat_audit import NATAuditService
    execute_service_command(ctx, NATAuditService, 'check_redundant_nat_gateways', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)