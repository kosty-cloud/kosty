import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def iam(ctx):
    """IAM operations"""
    pass

@iam.command('audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@common_options
@click.pass_context
def iam_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete IAM audit (cost + security)"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('security-audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@common_options
@click.pass_context
def iam_security_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM security audit only"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('check-root-access-keys')
@common_options
@click.pass_context
def iam_check_root_keys(ctx, organization, region, max_workers, regions, output):
    """Find root account access keys"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_root_access_keys', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@iam.command('cost-audit')
@click.option('--days', default=90, help='Days threshold for unused roles')
@common_options
@click.pass_context
def iam_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM cost optimization audit only"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('check-unused-roles')
@click.option('--days', default=90, help='Days threshold for unused roles')
@common_options
@click.pass_context
def iam_check_unused_roles(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused IAM roles"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_unused_roles', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('check-inactive-users')
@click.option('--days', default=90, help='Days threshold for inactive users')
@common_options
@click.pass_context
def iam_check_inactive_users(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find inactive IAM users"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_inactive_users', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('check-old-access-keys')
@click.option('--days', default=90, help='Days threshold for old access keys')
@common_options
@click.pass_context
def iam_check_old_keys(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find old IAM access keys"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_old_access_keys', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@iam.command('check-wildcard-policies')
@common_options
@click.pass_context
def iam_check_wildcard_policies(ctx, organization, region, max_workers, regions, output):
    """Find IAM policies with wildcard permissions"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_wildcard_policies', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@iam.command('check-admin-no-mfa')
@common_options
@click.pass_context
def iam_check_admin_no_mfa(ctx, organization, region, max_workers, regions, output):
    """Find admin users without MFA"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_admin_no_mfa', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@iam.command('check-weak-password-policy')
@common_options
@click.pass_context
def iam_check_weak_password(ctx, organization, region, max_workers, regions, output):
    """Find weak password policy"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_weak_password_policy', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@iam.command('check-no-password-rotation')
@common_options
@click.pass_context
def iam_check_no_rotation(ctx, organization, region, max_workers, regions, output):
    """Find users with no password rotation"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_no_password_rotation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@iam.command('check-cross-account-no-external-id')
@common_options
@click.pass_context
def iam_check_cross_account(ctx, organization, region, max_workers, regions, output):
    """Find cross-account roles without external ID"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_cross_account_no_external_id', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)