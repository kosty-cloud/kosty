import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def ecs(ctx):
    """ECS operations"""
    pass


@ecs.command('audit')
@common_options
@click.pass_context
def ecs_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ECS audit"""
    from ..services.ecs_audit import ECSAuditService
    execute_service_command(ctx, ECSAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@ecs.command('check-privileged-tasks')
@common_options
@click.pass_context
def ecs_check_privileged(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find task definitions with privileged containers"""
    from ..services.ecs_audit import ECSAuditService
    execute_service_command(ctx, ECSAuditService, 'check_privileged_tasks', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
