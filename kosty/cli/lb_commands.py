import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def lb(ctx):
    """LB operations"""
    pass

@lb.command('audit')
@common_options
@click.pass_context
def lb_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run LB complete audit"""
    execute_engine_command(ctx, 'LB', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lb.command('cost-audit')
@common_options
@click.pass_context
def lb_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run LB cost optimization audit"""
    execute_engine_command(ctx, 'LB', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lb.command('security-audit')
@common_options
@click.pass_context
def lb_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run LB security audit"""
    execute_engine_command(ctx, 'LB', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lb.command('check-no-targets')
@common_options
@click.pass_context
def lb_check_no_targets(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find load balancers with no healthy targets"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-001')

@lb.command('check-no-https')
@common_options
@click.pass_context
def lb_check_no_https(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find HTTP listeners without HTTPS redirect"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-002')

@lb.command('check-underutilized')
@common_options
@click.pass_context
def lb_check_underutilized(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find underutilized load balancers"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-003')

@lb.command('check-deprecated-tls')
@common_options
@click.pass_context
def lb_check_deprecated_tls(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find ALBs using deprecated TLS"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-004')

@lb.command('check-no-access-logs')
@common_options
@click.pass_context
def lb_check_no_access_logs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find ALBs without access logs"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-005')

@lb.command('check-classic-lb')
@common_options
@click.pass_context
def lb_check_classic_lb(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Classic Load Balancers"""
    execute_engine_command(ctx, 'LB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lb-006')

