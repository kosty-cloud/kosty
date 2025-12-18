import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def cloudwatch(ctx):
    """CloudWatch operations"""
    pass

@cloudwatch.command('audit')
@click.option('--days', default=30, help='Days threshold for unused resources')
@common_options
@click.pass_context
def cloudwatch_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete CloudWatch audit"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@cloudwatch.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused resources')
@common_options
@click.pass_context
def cloudwatch_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudWatch cost optimization audit only"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@cloudwatch.command('security-audit')
@common_options
@click.pass_context
def cloudwatch_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudWatch security audit only"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudwatch.command('check-unused-alarms')
@click.option('--days', default=30, help='Days threshold for alarm activity')
@common_options
@click.pass_context
def cloudwatch_check_alarms(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused CloudWatch alarms"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'check_unused_alarms', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@cloudwatch.command('check-log-retention')
@common_options
@click.pass_context
def cloudwatch_check_logs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find log groups without retention policies"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'check_log_groups_without_retention', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudwatch.command('check_unused_custom_metrics')
@click.option('--days', default=30, help='Days threshold for metrics activity')
@common_options
@click.pass_context
def cloudwatch_check_custom_metrics(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused custom metrics (no data in X days)"""
    from ..services.cloudwatch_audit import CloudWatchAuditService
    execute_service_command(ctx, CloudWatchAuditService, 'check_unused_custom_metrics', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)