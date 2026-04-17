import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def secretsmanager(ctx):
    """Secrets Manager operations"""
    pass


@secretsmanager.command('audit')
@click.option('--days', default=90, type=int, help='Days threshold for unused secrets (default: 90)')
@common_options
@click.pass_context
def sm_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete Secrets Manager audit"""
    from ..services.secretsmanager_audit import SecretsManagerAuditService
    execute_service_command(ctx, SecretsManagerAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@secretsmanager.command('cost-audit')
@click.option('--days', default=90, type=int, help='Days threshold for unused secrets (default: 90)')
@common_options
@click.pass_context
def sm_cost(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused secrets costing $0.40/mo each"""
    from ..services.secretsmanager_audit import SecretsManagerAuditService
    execute_service_command(ctx, SecretsManagerAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@secretsmanager.command('security-audit')
@common_options
@click.pass_context
def sm_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check secret rotation configuration"""
    from ..services.secretsmanager_audit import SecretsManagerAuditService
    execute_service_command(ctx, SecretsManagerAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@secretsmanager.command('check-unused-secrets')
@click.option('--days', default=90, type=int, help='Days threshold for unused secrets (default: 90)')
@common_options
@click.pass_context
def sm_check_unused(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find secrets never accessed but billed monthly"""
    from ..services.secretsmanager_audit import SecretsManagerAuditService
    execute_service_command(ctx, SecretsManagerAuditService, 'check_unused_secrets', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@secretsmanager.command('check-no-rotation')
@common_options
@click.pass_context
def sm_check_rotation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find secrets without automatic rotation"""
    from ..services.secretsmanager_audit import SecretsManagerAuditService
    execute_service_command(ctx, SecretsManagerAuditService, 'check_no_rotation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
