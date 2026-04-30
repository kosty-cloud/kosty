import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def sns(ctx):
    """SNS operations"""
    pass

@sns.command('audit')
@common_options
@click.pass_context
def sns_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SNS complete audit"""
    execute_engine_command(ctx, 'SNS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sns.command('cost-audit')
@common_options
@click.pass_context
def sns_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SNS cost optimization audit"""
    execute_engine_command(ctx, 'SNS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sns.command('security-audit')
@common_options
@click.pass_context
def sns_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SNS security audit"""
    execute_engine_command(ctx, 'SNS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@sns.command('check-no-encryption')
@common_options
@click.pass_context
def sns_check_no_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find topics without encryption"""
    execute_engine_command(ctx, 'SNS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sns-001')

