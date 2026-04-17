import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def sns(ctx):
    """SNS operations"""
    pass


@sns.command('audit')
@common_options
@click.pass_context
def sns_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SNS audit"""
    from ..services.sns_audit import SNSAuditService
    execute_service_command(ctx, SNSAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sns.command('check-no-encryption')
@common_options
@click.pass_context
def sns_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SNS topics without encryption"""
    from ..services.sns_audit import SNSAuditService
    execute_service_command(ctx, SNSAuditService, 'check_no_encryption', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
