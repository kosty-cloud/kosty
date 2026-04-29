import click
from .utils import common_options, execute_engine_command


@click.group()
@click.pass_context
def iam(ctx):
    """IAM operations"""
    pass


@iam.command('audit')
@common_options
@click.pass_context
def iam_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM complete audit"""
    execute_engine_command(ctx, 'IAM', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('cost-audit')
@common_options
@click.pass_context
def iam_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM cost optimization audit"""
    execute_engine_command(ctx, 'IAM', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('security-audit')
@common_options
@click.pass_context
def iam_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run IAM security audit"""
    execute_engine_command(ctx, 'IAM', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@iam.command('check-unused-roles')
@common_options
@click.pass_context
def iam_check_unused_roles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused IAM roles"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-001')


@iam.command('check-root-access-keys')
@common_options
@click.pass_context
def iam_check_root_access_keys(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check root account access keys"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-002')


@iam.command('check-root-mfa')
@common_options
@click.pass_context
def iam_check_root_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check root account MFA"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-003')


@iam.command('check-no-mfa')
@common_options
@click.pass_context
def iam_check_no_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find console users without MFA"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-004')


@iam.command('check-old-access-keys')
@common_options
@click.pass_context
def iam_check_old_access_keys(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find access keys older than 90 days"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-005')


@iam.command('check-unused-access-keys')
@common_options
@click.pass_context
def iam_check_unused_access_keys(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find active keys unused for 90+ days"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-006')


@iam.command('check-inactive-users')
@common_options
@click.pass_context
def iam_check_inactive_users(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find inactive users with active keys"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-007')


@iam.command('check-admin-no-mfa')
@common_options
@click.pass_context
def iam_check_admin_no_mfa(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find admin users without MFA"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-008')


@iam.command('check-wildcard-policies')
@common_options
@click.pass_context
def iam_check_wildcard_policies(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find policies with Action:* or Resource:*"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-009')


@iam.command('check-weak-password-policy')
@common_options
@click.pass_context
def iam_check_weak_password_policy(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find weak password policy"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-010')


@iam.command('check-no-password-rotation')
@common_options
@click.pass_context
def iam_check_no_password_rotation(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find missing password rotation policy"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-011')


@iam.command('check-cross-account-no-external-id')
@common_options
@click.pass_context
def iam_check_cross_account_no_external_id(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find cross-account roles without ExternalId"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-012')


@iam.command('check-inline-policies')
@common_options
@click.pass_context
def iam_check_inline_policies(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find inline policies"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-013')


@iam.command('check-passrole-wildcard')
@common_options
@click.pass_context
def iam_check_passrole_wildcard(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find iam:PassRole with wildcard resource"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-014')


@iam.command('check-assumerole-wildcard')
@common_options
@click.pass_context
def iam_check_assumerole_wildcard(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find sts:AssumeRole with wildcard"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-015')


@iam.command('check-shared-lambda-roles')
@common_options
@click.pass_context
def iam_check_shared_lambda_roles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Lambda functions sharing execution roles"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-016')


@iam.command('check-multiple-access-keys')
@common_options
@click.pass_context
def iam_check_multiple_access_keys(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find users with multiple active access keys"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-017')


@iam.command('check-privilege-escalation')
@click.option('--deep', is_flag=True, help='Run deep confirmation via SimulatePrincipalPolicy')
@common_options
@click.pass_context
def iam_check_privilege_escalation(ctx, deep, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect privilege escalation paths"""
    execute_engine_command(ctx, 'IAM', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-iam-018', deep=deep)

