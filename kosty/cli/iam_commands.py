import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def iam(ctx):
    """IAM operations"""
    pass

@iam.command('audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@click.option('--deep', is_flag=True, help='Confirm privilege escalation findings with SimulatePrincipalPolicy')
@common_options
@click.pass_context
def iam_audit(ctx, days, deep, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete IAM audit (cost + security)"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, deep=deep)

@iam.command('security-audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@click.option('--deep', is_flag=True, help='Confirm privilege escalation findings with SimulatePrincipalPolicy')
@common_options
@click.pass_context
def iam_security_audit(ctx, days, deep, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM security audit only"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, deep=deep)

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
def iam_check_cross_account(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find cross-account roles without external ID"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_cross_account_no_external_id', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-all-users-mfa')
@common_options
@click.pass_context
def iam_check_all_users_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find console users without MFA enabled"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_all_users_mfa', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-root-mfa')
@common_options
@click.pass_context
def iam_check_root_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if root account has MFA enabled"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_root_mfa', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-unused-access-keys')
@click.option('--days', default=90, help='Days threshold for unused keys')
@common_options
@click.pass_context
def iam_check_unused_keys(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find active access keys unused for 90+ days"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_unused_access_keys', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@iam.command('check-inline-policies')
@common_options
@click.pass_context
def iam_check_inline_policies(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect inline policies on users, groups, and roles"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_inline_policies', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-passrole-permissions')
@common_options
@click.pass_context
def iam_check_passrole(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Flag policies granting iam:PassRole with wildcard resource"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_passrole_permissions', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-shared-lambda-roles')
@common_options
@click.pass_context
def iam_check_shared_lambda_roles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Lambda functions sharing the same execution role"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_shared_lambda_roles', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-multiple-active-keys')
@common_options
@click.pass_context
def iam_check_multiple_keys(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find users with multiple active access keys"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_multiple_active_keys', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-wildcard-assume-role')
@common_options
@click.pass_context
def iam_check_wildcard_assume(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Flag policies granting sts:AssumeRole with wildcard resource"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_wildcard_assume_role', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-privilege-escalation')
@click.option('--deep', is_flag=True, help='Confirm findings with SimulatePrincipalPolicy (slower, zero false positives)')
@common_options
@click.pass_context
def iam_check_privesc(ctx, deep, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect IAM principals with privilege escalation paths (21 patterns)"""
    from ..services.iam_audit import IAMAuditService
    execute_service_command(ctx, IAMAuditService, 'check_privilege_escalation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, deep=deep)
