import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def secretsmanager(ctx):
    """SecretsManager operations"""
    pass


@secretsmanager.command('audit')
@common_options
@click.pass_context
def secretsmanager_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SecretsManager complete audit"""
    execute_engine_command(ctx, 'SecretsManager', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@secretsmanager.command('cost-audit')
@common_options
@click.pass_context
def secretsmanager_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SecretsManager cost optimization audit"""
    execute_engine_command(ctx, 'SecretsManager', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@secretsmanager.command('security-audit')
@common_options
@click.pass_context
def secretsmanager_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SecretsManager security audit"""
    execute_engine_command(ctx, 'SecretsManager', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@secretsmanager.command('check-unused')
@common_options
@click.pass_context
def secretsmanager_check_unused(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find secrets never accessed"""
    execute_engine_command(ctx, 'SecretsManager', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-secretsmanager-001')


@secretsmanager.command('check-no-rotation')
@common_options
@click.pass_context
def secretsmanager_check_no_rotation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find secrets without rotation"""
    execute_engine_command(ctx, 'SecretsManager', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-secretsmanager-002')

