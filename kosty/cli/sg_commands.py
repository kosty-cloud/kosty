import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def sg(ctx):
    """SG operations"""
    pass

@sg.command('audit')
@common_options
@click.pass_context
def sg_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SG complete audit"""
    execute_engine_command(ctx, 'SG', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sg.command('cost-audit')
@common_options
@click.pass_context
def sg_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SG cost optimization audit"""
    execute_engine_command(ctx, 'SG', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sg.command('security-audit')
@common_options
@click.pass_context
def sg_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SG security audit"""
    execute_engine_command(ctx, 'SG', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sg.command('check-ssh-rdp-open')
@common_options
@click.pass_context
def sg_check_ssh_rdp_open(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SGs with SSH/RDP open to internet"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-001')

@sg.command('check-all-ports-open')
@common_options
@click.pass_context
def sg_check_all_ports_open(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SGs with all ports open"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-002')

@sg.command('check-unused')
@common_options
@click.pass_context
def sg_check_unused(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused security groups"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-003')

@sg.command('check-database-ports')
@common_options
@click.pass_context
def sg_check_database_ports(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SGs with database ports open"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-004')

@sg.command('check-wide-cidr')
@common_options
@click.pass_context
def sg_check_wide_cidr(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SGs with wide CIDR rules"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-005')

@sg.command('check-complex')
@common_options
@click.pass_context
def sg_check_complex(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find overly complex security groups"""
    execute_engine_command(ctx, 'SG', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sg-006')

