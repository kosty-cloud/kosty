import click
from .utils import common_options, execute_engine_command

@click.group(name='lambda')
@click.pass_context
def lambda_func(ctx):
    """Lambda operations"""
    pass

@lambda_func.command('audit')
@common_options
@click.pass_context
def lambda_func_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Lambda complete audit"""
    execute_engine_command(ctx, 'Lambda', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lambda_func.command('cost-audit')
@common_options
@click.pass_context
def lambda_func_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Lambda cost optimization audit"""
    execute_engine_command(ctx, 'Lambda', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lambda_func.command('security-audit')
@common_options
@click.pass_context
def lambda_func_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Lambda security audit"""
    execute_engine_command(ctx, 'Lambda', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@lambda_func.command('check-unused')
@common_options
@click.pass_context
def lambda_func_check_unused(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find functions with 0 invocations"""
    execute_engine_command(ctx, 'Lambda', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lambda-001')

@lambda_func.command('check-public')
@common_options
@click.pass_context
def lambda_func_check_public(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find publicly accessible functions"""
    execute_engine_command(ctx, 'Lambda', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lambda-002')

@lambda_func.command('check-outdated-runtime')
@common_options
@click.pass_context
def lambda_func_check_outdated_runtime(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find functions using outdated runtimes"""
    execute_engine_command(ctx, 'Lambda', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lambda-003')

@lambda_func.command('check-over-provisioned')
@common_options
@click.pass_context
def lambda_func_check_over_provisioned(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find over-provisioned Lambda memory"""
    execute_engine_command(ctx, 'Lambda', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lambda-004')

@lambda_func.command('check-long-timeout')
@common_options
@click.pass_context
def lambda_func_check_long_timeout(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find functions with timeout >5 minutes"""
    execute_engine_command(ctx, 'Lambda', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-lambda-005')

