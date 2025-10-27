import click
from .utils import common_options, execute_service_command

@click.group(name='lambda')
@click.pass_context
def lambda_func(ctx):
    """Lambda operations"""
    pass

@lambda_func.command('audit')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete Lambda audit"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'audit', output, organization, region, max_workers, regions, days=days)

@lambda_func.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run Lambda cost optimization audit only"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'cost_audit', output, organization, region, max_workers, regions, days=days)

@lambda_func.command('check-unused-functions')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_check_unused(ctx, days, organization, region, max_workers, regions, output):
    """Find unused Lambda functions"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'check_unused_functions', output, organization, region, max_workers, regions, days=days)

@lambda_func.command('security-audit')
@common_options
@click.pass_context
def lambda_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Lambda security audit only"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'security_audit', output, organization, region, max_workers, regions)

@lambda_func.command('check-over-provisioned-memory')
@common_options
@click.pass_context
def lambda_check_memory(ctx, organization, region, max_workers, regions, output):
    """Find over-provisioned Lambda functions"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'check_over_provisioned_memory', output, organization, region, max_workers, regions)

@lambda_func.command('check-long-timeout-functions')
@common_options
@click.pass_context
def lambda_check_timeout(ctx, organization, region, max_workers, regions, output):
    """Find Lambda functions with long timeouts"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'check_long_timeout_functions', output, organization, region, max_workers, regions)

@lambda_func.command('check-public-functions')
@common_options
@click.pass_context
def lambda_check_public(ctx, organization, region, max_workers, regions, output):
    """Find publicly accessible Lambda functions"""
    from ..services.lambda_audit import LambdaAuditService
    execute_service_command(ctx, LambdaAuditService, 'check_public_functions', output, organization, region, max_workers, regions)