import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def eip(ctx):
    """Elastic IP operations"""
    pass

@eip.command('audit')
@common_options
@click.pass_context
def eip_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete EIP audit"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'audit', output, organization, region, max_workers, regions)

@eip.command('cost-audit')
@common_options
@click.pass_context
def eip_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run EIP cost optimization audit only"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'cost_audit', output, organization, region, max_workers, regions)

@eip.command('security-audit')
@common_options
@click.pass_context
def eip_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run EIP security audit only"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'security_audit', output, organization, region, max_workers, regions)

@eip.command('check-unattached-eips')
@common_options
@click.pass_context
def eip_check_unattached(ctx, organization, region, max_workers, regions, output):
    """Find unattached Elastic IPs"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'check_unattached_eips', output, organization, region, max_workers, regions)

@eip.command('check-eips-on-stopped-instances')
@common_options
@click.pass_context
def eip_check_stopped_instances(ctx, organization, region, max_workers, regions, output):
    """Find EIPs attached to stopped instances"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'check_eips_on_stopped_instances', output, organization, region, max_workers, regions)

@eip.command('check-dangerous-sg-rules')
@common_options
@click.pass_context
def eip_check_dangerous_sg(ctx, organization, region, max_workers, regions, output):
    """Find EIPs with dangerous security group rules"""
    from ..services.eip_audit import EIPAuditService
    execute_service_command(ctx, EIPAuditService, 'check_eips_with_dangerous_sg_rules', output, organization, region, max_workers, regions)