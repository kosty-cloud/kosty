import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def sg(ctx):
    """Security Group operations"""
    pass

@sg.command('audit')
@common_options
@click.pass_context
def sg_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete Security Group audit"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('cost-audit')
@common_options
@click.pass_context
def sg_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run Security Group cost optimization audit only"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('security-audit')
@common_options
@click.pass_context
def sg_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Security Group security audit only"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('check-unused-groups')
@common_options
@click.pass_context
def sg_check_unused(ctx, organization, region, max_workers, regions, output):
    """Find unused security groups"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'check_unused_groups', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('check-ssh-rdp-open')
@common_options
@click.pass_context
def sg_check_ssh_rdp(ctx, organization, region, max_workers, regions, output):
    """Find security groups with SSH/RDP open to 0.0.0.0/0"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'check_ssh_rdp_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('check-database-ports-open')
@common_options
@click.pass_context
def sg_check_db_ports(ctx, organization, region, max_workers, regions, output):
    """Find security groups with database ports open to 0.0.0.0/0"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'check_database_ports_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('check-all-ports-open')
@common_options
@click.pass_context
def sg_check_all_ports(ctx, organization, region, max_workers, regions, output):
    """Find security groups with all ports open to 0.0.0.0/0"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'check_all_ports_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@sg.command('check-complex-security-groups')
@click.option('--rule-threshold', default=50, help='Rule count threshold for complex security groups')
@common_options
@click.pass_context
def sg_check_complex(ctx, rule_threshold, organization, region, max_workers, regions, output, cross_account_role, org_admin_account_id):
    """Find security groups with >rule_threshold rules"""
    from ..services.sg_audit import SGAuditService
    execute_service_command(ctx, SGAuditService, 'check_complex_security_groups', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, rule_threshold=rule_threshold)