import click
from .utils import common_options, execute_service_command


@click.group(name='bedrock')
@click.pass_context
def bedrock_cmd(ctx):
    """Amazon Bedrock operations"""
    pass


@bedrock_cmd.command('audit')
@common_options
@click.pass_context
def bedrock_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete Bedrock audit (cost + security)"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock_cmd.command('cost-audit')
@common_options
@click.pass_context
def bedrock_cost(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check Bedrock budget and spend controls"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock_cmd.command('security-audit')
@common_options
@click.pass_context
def bedrock_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check Bedrock logging and security configuration"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock_cmd.command('check-no-logging')
@common_options
@click.pass_context
def bedrock_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock model invocation logging is enabled"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_logging', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock_cmd.command('check-no-budget-limits')
@common_options
@click.pass_context
def bedrock_check_budget(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if AWS Budget exists for Bedrock spend"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_budget_limits', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
