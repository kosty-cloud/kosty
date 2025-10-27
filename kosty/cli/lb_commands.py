import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def lb(ctx):
    """Load Balancer operations"""
    pass

@lb.command('audit')
@common_options
@click.pass_context
def lb_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete Load Balancer audit"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'audit', output, organization, region, max_workers, regions)

@lb.command('cost-audit')
@common_options
@click.pass_context
def lb_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run Load Balancer cost optimization audit only"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'cost_audit', output, organization, region, max_workers, regions)

@lb.command('security-audit')
@common_options
@click.pass_context
def lb_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Load Balancer security audit only"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'security_audit', output, organization, region, max_workers, regions)

@lb.command('check-no-healthy-targets')
@common_options
@click.pass_context
def lb_check_no_targets(ctx, organization, region, max_workers, regions, output):
    """Find load balancers with no healthy targets"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_lbs_with_no_healthy_targets', output, organization, region, max_workers, regions)

@lb.command('check-underutilized-lbs')
@common_options
@click.pass_context
def lb_check_underutilized(ctx, organization, region, max_workers, regions, output):
    """Find underutilized load balancers"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_underutilized_lbs', output, organization, region, max_workers, regions)

@lb.command('check-classic-lbs')
@common_options
@click.pass_context
def lb_check_classic(ctx, organization, region, max_workers, regions, output):
    """Find Classic Load Balancers (should be ALB/NLB)"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_classic_lbs', output, organization, region, max_workers, regions)

@lb.command('check-http-without-https-redirect')
@common_options
@click.pass_context
def lb_check_http_redirect(ctx, organization, region, max_workers, regions, output):
    """Find HTTP listeners without HTTPS redirect"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_http_without_https_redirect', output, organization, region, max_workers, regions)

@lb.command('check-deprecated-tls-versions')
@common_options
@click.pass_context
def lb_check_tls(ctx, organization, region, max_workers, regions, output):
    """Find load balancers with deprecated TLS versions"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_deprecated_tls_versions', output, organization, region, max_workers, regions)

@lb.command('check-lbs-without-access-logs')
@common_options
@click.pass_context
def lb_check_access_logs(ctx, organization, region, max_workers, regions, output):
    """Find load balancers without access logs"""
    from ..services.lb_audit import LBAuditService
    execute_service_command(ctx, LBAuditService, 'check_lbs_without_access_logs', output, organization, region, max_workers, regions)