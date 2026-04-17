import click
import asyncio
from .utils import common_options, execute_service_command


@click.group(name='ai')
@click.pass_context
def ai_audit(ctx):
    """AI/ML audit — Bedrock + SageMaker cost & security"""
    pass


# --- Top-level ai-audit commands (runs both services) ---

@ai_audit.command('audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_full_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full AI audit (Bedrock + SageMaker)"""
    from ..services.bedrock_audit import BedrockAuditService
    from ..services.sagemaker_audit import SageMakerAuditService
    print("\n🤖 Bedrock Audit")
    print("─" * 40)
    execute_service_command(ctx, BedrockAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)
    print("\n🤖 SageMaker Audit")
    print("─" * 40)
    execute_service_command(ctx, SageMakerAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@ai_audit.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI cost audit (Bedrock + SageMaker)"""
    from ..services.bedrock_audit import BedrockAuditService
    from ..services.sagemaker_audit import SageMakerAuditService
    print("\n🤖 Bedrock Cost Audit")
    print("─" * 40)
    execute_service_command(ctx, BedrockAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)
    print("\n🤖 SageMaker Cost Audit")
    print("─" * 40)
    execute_service_command(ctx, SageMakerAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@ai_audit.command('security-audit')
@common_options
@click.pass_context
def ai_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI security audit (Bedrock + SageMaker)"""
    from ..services.bedrock_audit import BedrockAuditService
    from ..services.sagemaker_audit import SageMakerAuditService
    print("\n🤖 Bedrock Security Audit")
    print("─" * 40)
    execute_service_command(ctx, BedrockAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
    print("\n🤖 SageMaker Security Audit")
    print("─" * 40)
    execute_service_command(ctx, SageMakerAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


# --- Bedrock subgroup ---

@ai_audit.group()
@click.pass_context
def bedrock(ctx):
    """Bedrock audit commands"""
    pass


@bedrock.command('audit')
@common_options
@click.pass_context
def bedrock_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full Bedrock audit"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('cost-audit')
@common_options
@click.pass_context
def bedrock_cost(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock cost audit"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('security-audit')
@common_options
@click.pass_context
def bedrock_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock security audit"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-logging')
@common_options
@click.pass_context
def bedrock_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock invocation logging is enabled"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_logging', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-budget-limits')
@common_options
@click.pass_context
def bedrock_check_budget(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if AWS Budget exists for Bedrock spend"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_budget_limits', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-guardrails')
@common_options
@click.pass_context
def bedrock_check_guardrails(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock Guardrails are configured"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_guardrails', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-shadow-ai')
@common_options
@click.pass_context
def bedrock_check_shadow(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find IAM roles with AI permissions not tagged as approved"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_shadow_ai', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def bedrock_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for Bedrock"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_vpc_endpoint', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-custom-model-no-kms')
@common_options
@click.pass_context
def bedrock_check_kms(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if custom models are encrypted with customer-managed KMS"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_custom_model_no_kms', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-prompt-caching')
@common_options
@click.pass_context
def bedrock_check_caching(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if prompt caching is being used"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_prompt_caching', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-inference-profiles')
@common_options
@click.pass_context
def bedrock_check_profiles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Application Inference Profiles are configured"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_no_inference_profiles', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-tpm-quota')
@common_options
@click.pass_context
def bedrock_check_tpm(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock TPM quota usage is above 80%"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_tpm_quota_high_usage', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-cross-account-model-access')
@common_options
@click.pass_context
def bedrock_check_cross_account(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check S3 bucket policies on custom model training data for cross-account access"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_cross_account_model_access', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


# --- SageMaker subgroup ---

@ai_audit.group()
@click.pass_context
def sagemaker(ctx):
    """SageMaker audit commands"""
    pass


@sagemaker.command('audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full SageMaker audit"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_cost(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker cost audit"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('security-audit')
@common_options
@click.pass_context
def sagemaker_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker security audit"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-idle-endpoints')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_check_idle(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find endpoints with zero invocations"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_idle_endpoints', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('check-zombie-notebooks')
@common_options
@click.pass_context
def sagemaker_check_notebooks(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find running notebook instances"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_zombie_notebooks', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-no-spot-training')
@common_options
@click.pass_context
def sagemaker_check_spot(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find training jobs not using Spot instances"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_no_spot_training', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-no-checkpointing')
@common_options
@click.pass_context
def sagemaker_check_checkpoint(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Spot training jobs without checkpointing"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_no_checkpointing', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def sagemaker_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for SageMaker"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_no_vpc_endpoint', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-notebook-direct-internet')
@common_options
@click.pass_context
def sagemaker_check_internet(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with direct internet access"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_notebook_direct_internet', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-notebook-root-access')
@common_options
@click.pass_context
def sagemaker_check_root(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with root access enabled"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_notebook_root_access', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
