import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def eip(ctx):
    """EIP operations"""
    pass

@eip.command('audit')
@common_options
@click.pass_context
def eip_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EIP complete audit"""
    execute_engine_command(ctx, 'EIP', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@eip.command('cost-audit')
@common_options
@click.pass_context
def eip_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EIP cost optimization audit"""
    execute_engine_command(ctx, 'EIP', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@eip.command('security-audit')
@common_options
@click.pass_context
def eip_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EIP security audit"""
    execute_engine_command(ctx, 'EIP', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@eip.command('check-unattached')
@common_options
@click.pass_context
def eip_check_unattached(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unattached Elastic IPs"""
    execute_engine_command(ctx, 'EIP', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-eip-001')

@eip.command('check-stopped-instance')
@common_options
@click.pass_context
def eip_check_stopped_instance(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find EIPs on stopped instances"""
    execute_engine_command(ctx, 'EIP', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-eip-002')

@eip.command('check-dangerous-sg')
@common_options
@click.pass_context
def eip_check_dangerous_sg(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find EIPs on instances with dangerous SG rules"""
    execute_engine_command(ctx, 'EIP', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-eip-003')

