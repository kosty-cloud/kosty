import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def nat(ctx):
    """NAT operations"""
    pass


@nat.command('audit')
@common_options
@click.pass_context
def nat_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run NAT complete audit"""
    execute_engine_command(ctx, 'NAT', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@nat.command('cost-audit')
@common_options
@click.pass_context
def nat_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run NAT cost optimization audit"""
    execute_engine_command(ctx, 'NAT', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@nat.command('security-audit')
@common_options
@click.pass_context
def nat_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run NAT security audit"""
    execute_engine_command(ctx, 'NAT', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@nat.command('check-zero-traffic')
@common_options
@click.pass_context
def nat_check_zero_traffic(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find NAT Gateways with zero traffic"""
    execute_engine_command(ctx, 'NAT', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-nat-001')


@nat.command('check-redundant')
@common_options
@click.pass_context
def nat_check_redundant(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find redundant NAT Gateways in same AZ"""
    execute_engine_command(ctx, 'NAT', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-nat-002')

