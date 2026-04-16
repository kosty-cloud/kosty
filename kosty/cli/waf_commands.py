import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def waf(ctx):
    """WAFv2 operations"""
    pass


@waf.command('audit')
@common_options
@click.pass_context
def waf_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete WAFv2 audit (cost + security)"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('security-audit')
@common_options
@click.pass_context
def waf_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run WAFv2 security audit only"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('cost-audit')
@common_options
@click.pass_context
def waf_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run WAFv2 cost audit only"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-unassociated-acls')
@common_options
@click.pass_context
def waf_check_unassociated(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Web ACLs not associated with any resource"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_unassociated_acls', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-missing-managed-rules')
@common_options
@click.pass_context
def waf_check_managed_rules(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify presence of AWS Managed Rules (Core Rule Set & IP Reputation)"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_missing_managed_rules', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-no-rate-based-rule')
@common_options
@click.pass_context
def waf_check_rate_rule(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check for rate-based rules (DDoS/brute-force protection)"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_no_rate_based_rule', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-no-logging')
@common_options
@click.pass_context
def waf_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Verify WAF logging is enabled"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_no_logging', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-default-count-action')
@common_options
@click.pass_context
def waf_check_count_action(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Ensure critical rules are not set to Count mode"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_default_count_action', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@waf.command('check-no-bot-control')
@common_options
@click.pass_context
def waf_check_bot_control(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check for Bot Control managed rule group"""
    from ..services.waf_audit import WAFAuditService
    execute_service_command(ctx, WAFAuditService, 'check_no_bot_control', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
