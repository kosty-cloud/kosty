import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def sqs(ctx):
    """SQS operations"""
    pass


@sqs.command('audit')
@common_options
@click.pass_context
def sqs_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SQS complete audit"""
    execute_engine_command(ctx, 'SQS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sqs.command('cost-audit')
@common_options
@click.pass_context
def sqs_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SQS cost optimization audit"""
    execute_engine_command(ctx, 'SQS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sqs.command('security-audit')
@common_options
@click.pass_context
def sqs_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SQS security audit"""
    execute_engine_command(ctx, 'SQS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sqs.command('check-no-encryption')
@common_options
@click.pass_context
def sqs_check_no_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find queues without encryption"""
    execute_engine_command(ctx, 'SQS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sqs-001')

