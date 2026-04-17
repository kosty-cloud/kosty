import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def vpc(ctx):
    """VPC operations"""
    pass


@vpc.command('audit')
@common_options
@click.pass_context
def vpc_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete VPC audit"""
    from ..services.vpc_audit import VPCAuditService
    execute_service_command(ctx, VPCAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('security-audit')
@common_options
@click.pass_context
def vpc_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run VPC security audit"""
    from ..services.vpc_audit import VPCAuditService
    execute_service_command(ctx, VPCAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('check-no-flow-logs')
@common_options
@click.pass_context
def vpc_check_flow_logs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find VPCs without Flow Logs enabled"""
    from ..services.vpc_audit import VPCAuditService
    execute_service_command(ctx, VPCAuditService, 'check_no_flow_logs', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('check-default-sg-open')
@common_options
@click.pass_context
def vpc_check_default_sg(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find default security groups with inbound rules"""
    from ..services.vpc_audit import VPCAuditService
    execute_service_command(ctx, VPCAuditService, 'check_default_sg_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
