import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def route53(ctx):
    """Route53 operations"""
    pass

@route53.command('audit')
@common_options
@click.pass_context
def route53_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete Route53 audit"""
    from ..services.route53_audit import Route53AuditService
    execute_service_command(ctx, Route53AuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('cost-audit')
@common_options
@click.pass_context
def route53_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Route53 cost optimization audit only"""
    from ..services.route53_audit import Route53AuditService
    execute_service_command(ctx, Route53AuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('security-audit')
@common_options
@click.pass_context
def route53_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Route53 security audit only"""
    from ..services.route53_audit import Route53AuditService
    execute_service_command(ctx, Route53AuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@route53.command('check-unused-hosted-zones')
@common_options
@click.pass_context
def route53_check_unused(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused Route53 hosted zones"""
    from ..services.route53_audit import Route53AuditService
    execute_service_command(ctx, Route53AuditService, 'check_unused_hosted_zones', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)