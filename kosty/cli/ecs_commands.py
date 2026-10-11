import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def ecs(ctx):
    """ECS operations"""
    pass

@ecs.command('audit')
@common_options
@click.pass_context
def ecs_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ECS complete audit"""
    execute_engine_command(ctx, 'ECS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ecs.command('cost-audit')
@common_options
@click.pass_context
def ecs_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ECS cost optimization audit"""
    execute_engine_command(ctx, 'ECS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ecs.command('security-audit')
@common_options
@click.pass_context
def ecs_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ECS security audit"""
    execute_engine_command(ctx, 'ECS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@ecs.command('check-privileged')
@common_options
@click.pass_context
def ecs_check_privileged(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find privileged task definitions"""
    execute_engine_command(ctx, 'ECS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ecs-001')

