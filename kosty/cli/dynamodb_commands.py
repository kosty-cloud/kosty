import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def dynamodb(ctx):
    """DynamoDB operations"""
    pass

@dynamodb.command('audit')
@common_options
@click.pass_context
def dynamodb_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run DynamoDB complete audit"""
    execute_engine_command(ctx, 'DynamoDB', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@dynamodb.command('cost-audit')
@common_options
@click.pass_context
def dynamodb_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run DynamoDB cost optimization audit"""
    execute_engine_command(ctx, 'DynamoDB', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@dynamodb.command('security-audit')
@common_options
@click.pass_context
def dynamodb_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run DynamoDB security audit"""
    execute_engine_command(ctx, 'DynamoDB', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@dynamodb.command('check-idle-tables')
@common_options
@click.pass_context
def dynamodb_check_idle_tables(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find tables with near-zero consumed capacity"""
    execute_engine_command(ctx, 'DynamoDB', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-dynamodb-001')

