import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def dynamodb(ctx):
    """DynamoDB operations"""
    pass

@dynamodb.command('audit')
@click.option('--days', default=7, help='Days threshold for idle tables')
@common_options
@click.pass_context
def dynamodb_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete DynamoDB audit"""
    from ..services.dynamodb_audit import DynamoDBAuditService
    execute_service_command(ctx, DynamoDBAuditService, 'audit', output, organization, region, max_workers, regions, days=days)

@dynamodb.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for idle tables')
@common_options
@click.pass_context
def dynamodb_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run DynamoDB cost optimization audit only"""
    from ..services.dynamodb_audit import DynamoDBAuditService
    execute_service_command(ctx, DynamoDBAuditService, 'cost_audit', output, organization, region, max_workers, regions, days=days)

@dynamodb.command('security-audit')
@common_options
@click.pass_context
def dynamodb_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run DynamoDB security audit only"""
    from ..services.dynamodb_audit import DynamoDBAuditService
    execute_service_command(ctx, DynamoDBAuditService, 'security_audit', output, organization, region, max_workers, regions)

@dynamodb.command('find-idle-tables')
@click.option('--days', default=7, help='Days threshold for table activity')
@common_options
@click.pass_context
def dynamodb_find_idle(ctx, days, organization, region, max_workers, regions, output):
    """Find idle DynamoDB tables (alternative method)"""
    from ..services.dynamodb_audit import DynamoDBAuditService
    execute_service_command(ctx, DynamoDBAuditService, 'find_idle_tables', output, organization, region, max_workers, regions, days=days)