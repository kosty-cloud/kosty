import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def sqs(ctx):
    """SQS operations"""
    pass


@sqs.command('audit')
@common_options
@click.pass_context
def sqs_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SQS audit"""
    from ..services.sqs_audit import SQSAuditService
    execute_service_command(ctx, SQSAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sqs.command('check-no-encryption')
@common_options
@click.pass_context
def sqs_check_encryption(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find SQS queues without encryption"""
    from ..services.sqs_audit import SQSAuditService
    execute_service_command(ctx, SQSAuditService, 'check_no_encryption', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
