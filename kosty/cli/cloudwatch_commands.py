import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def cloudwatch(ctx):
    """CloudWatch operations"""
    pass

@cloudwatch.command('audit')
@common_options
@click.pass_context
def cloudwatch_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudWatch complete audit"""
    execute_engine_command(ctx, 'CloudWatch', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudwatch.command('cost-audit')
@common_options
@click.pass_context
def cloudwatch_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudWatch cost optimization audit"""
    execute_engine_command(ctx, 'CloudWatch', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudwatch.command('security-audit')
@common_options
@click.pass_context
def cloudwatch_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudWatch security audit"""
    execute_engine_command(ctx, 'CloudWatch', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudwatch.command('check-no-retention')
@common_options
@click.pass_context
def cloudwatch_check_no_retention(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find log groups without retention policy"""
    execute_engine_command(ctx, 'CloudWatch', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudwatch-001')

@cloudwatch.command('check-stale-alarms')
@common_options
@click.pass_context
def cloudwatch_check_stale_alarms(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find alarms with no state changes"""
    execute_engine_command(ctx, 'CloudWatch', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudwatch-002')

@cloudwatch.command('check-unused-metrics')
@click.option('--max-metrics', default=50, help='Max metrics to check')
@common_options
@click.pass_context
def cloudwatch_check_unused_metrics(ctx, max_metrics, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused custom metrics"""
    execute_engine_command(ctx, 'CloudWatch', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudwatch-003', max_metrics=max_metrics)

