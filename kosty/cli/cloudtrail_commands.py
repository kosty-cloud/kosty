import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def cloudtrail(ctx):
    """CloudTrail operations"""
    pass

@cloudtrail.command('audit')
@common_options
@click.pass_context
def cloudtrail_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudTrail complete audit"""
    execute_engine_command(ctx, 'CloudTrail', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudtrail.command('cost-audit')
@common_options
@click.pass_context
def cloudtrail_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudTrail cost optimization audit"""
    execute_engine_command(ctx, 'CloudTrail', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudtrail.command('security-audit')
@common_options
@click.pass_context
def cloudtrail_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run CloudTrail security audit"""
    execute_engine_command(ctx, 'CloudTrail', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@cloudtrail.command('check-enabled')
@common_options
@click.pass_context
def cloudtrail_check_enabled(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify CloudTrail is enabled"""
    execute_engine_command(ctx, 'CloudTrail', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudtrail-001')

@cloudtrail.command('check-log-validation')
@common_options
@click.pass_context
def cloudtrail_check_log_validation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify log file validation"""
    execute_engine_command(ctx, 'CloudTrail', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudtrail-002')

@cloudtrail.command('check-encryption')
@common_options
@click.pass_context
def cloudtrail_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify CloudTrail logs are encrypted"""
    execute_engine_command(ctx, 'CloudTrail', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-cloudtrail-003')

