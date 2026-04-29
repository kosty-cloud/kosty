import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def vpc(ctx):
    """VPC operations"""
    pass


@vpc.command('audit')
@common_options
@click.pass_context
def vpc_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run VPC complete audit"""
    execute_engine_command(ctx, 'VPC', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('cost-audit')
@common_options
@click.pass_context
def vpc_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run VPC cost optimization audit"""
    execute_engine_command(ctx, 'VPC', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('security-audit')
@common_options
@click.pass_context
def vpc_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run VPC security audit"""
    execute_engine_command(ctx, 'VPC', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@vpc.command('check-no-flow-logs')
@common_options
@click.pass_context
def vpc_check_no_flow_logs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find VPCs without Flow Logs"""
    execute_engine_command(ctx, 'VPC', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-vpc-001')


@vpc.command('check-default-sg')
@common_options
@click.pass_context
def vpc_check_default_sg(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find default SGs with inbound rules"""
    execute_engine_command(ctx, 'VPC', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-vpc-002')

