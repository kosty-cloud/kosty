import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def waf(ctx):
    """WAF operations"""
    pass


@waf.command('audit')
@common_options
@click.pass_context
def waf_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run WAF complete audit"""
    execute_engine_command(ctx, 'WAF', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('cost-audit')
@common_options
@click.pass_context
def waf_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run WAF cost optimization audit"""
    execute_engine_command(ctx, 'WAF', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('security-audit')
@common_options
@click.pass_context
def waf_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run WAF security audit"""
    execute_engine_command(ctx, 'WAF', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-unassociated')
@common_options
@click.pass_context
def waf_check_unassociated(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Web ACLs not associated with any resource"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-001')


@waf.command('check-managed-rules')
@common_options
@click.pass_context
def waf_check_managed_rules(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify AWS Managed Rules"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-002')


@waf.command('check-rate-limiting')
@common_options
@click.pass_context
def waf_check_rate_limiting(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check for rate-based rules"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-003')


@waf.command('check-logging')
@common_options
@click.pass_context
def waf_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify WAF logging is enabled"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-004')


@waf.command('check-count-mode')
@common_options
@click.pass_context
def waf_check_count_mode(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Ensure rules not in Count mode"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-005')


@waf.command('check-bot-control')
@common_options
@click.pass_context
def waf_check_bot_control(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check for Bot Control rule group"""
    execute_engine_command(ctx, 'WAF', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-waf-006')

