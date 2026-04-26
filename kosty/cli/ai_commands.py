import click
import asyncio
import json
from datetime import datetime
from .utils import common_options, execute_service_command
from ..core.executor import ServiceExecutor
from ..core.config import ConfigManager


def _get_ai_executor_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id):
    """Resolve config and CLI params for AI audit execution"""
    from .utils import get_profile_from_context, get_effective_params
    profile_name = get_profile_from_context(ctx, profile)

    try:
        config_manager = ConfigManager(config_file=ctx.obj.get('config_file'), profile=profile_name)
        session = config_manager.get_aws_session()
        final_config = config_manager.merge_with_cli_args({
            'organization': organization, 'region': region, 'regions': regions,
            'max_workers': max_workers, 'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        })

        if final_config.get('regions'):
            reg_list = [r.strip() for r in final_config['regions'].split(',')] if isinstance(final_config['regions'], str) else final_config['regions']
        elif final_config.get('region'):
            reg_list = [final_config['region']]
        else:
            reg_list = ['us-east-1']

        return {
            'org': final_config.get('organization', False),
            'reg_list': reg_list,
            'workers': final_config.get('max_workers', 10),
            'role_name': final_config.get('cross_account_role', 'OrganizationAccountAccessRole'),
            'admin_account': final_config.get('org_admin_account_id'),
            'config_manager': config_manager,
            'session': session
        }
    except Exception:
        config_manager = None
        session = None
        org, reg_list, workers, role_name, admin_account = get_effective_params(
            ctx, organization, region, max_workers, regions, cross_account_role, org_admin_account_id
        )
        return {
            'org': org, 'reg_list': reg_list, 'workers': workers,
            'role_name': role_name, 'admin_account': admin_account,
            'config_manager': config_manager, 'session': session
        }


async def _run_combined_ai_audit(params, method, output, save_to, **kwargs):
    """Run Bedrock + SageMaker, merge results, output once"""
    from ..services.bedrock_audit import BedrockAuditService
    from ..services.sagemaker_audit import SageMakerAuditService

    combined_results = {}

    for label, service_class in [('Bedrock', BedrockAuditService), ('SageMaker', SageMakerAuditService)]:
        print(f"\n🤖 {label} Audit")
        print("─" * 40)

        service = service_class()
        executor = ServiceExecutor(
            service, params['org'], params['reg_list'], params['workers'],
            params['role_name'], params['admin_account'],
            config_manager=params['config_manager'], session=params['session']
        )
        results = await executor.execute(method, 'console', **kwargs)

        for account_id, items in results.items():
            if account_id not in combined_results:
                combined_results[account_id] = []
            if isinstance(items, list):
                combined_results[account_id].extend(items)

    total = sum(len(v) for v in combined_results.values())

    if output in ['json', 'csv', 'all']:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = list(combined_results.keys())[0] if combined_results else 'unknown'

        if output in ['json', 'all']:
            json_output = {
                'scan_timestamp': datetime.now().isoformat(),
                'method': f'ai_{method}',
                'total_issues': total,
                'results': combined_results
            }
            filename = f"kosty_ai_{account_id}_{timestamp}.json"
            if save_to:
                import os
                filepath = os.path.join(save_to, filename)
                os.makedirs(save_to, exist_ok=True)
            else:
                filepath = filename
            with open(filepath, 'w') as f:
                json.dump(json_output, f, indent=2, default=str)
            print(f"\n📄 AI audit JSON report saved: {filepath}")

        if output in ['csv', 'all']:
            import csv
            from io import StringIO
            filename = f"kosty_ai_{account_id}_{timestamp}.csv"
            if save_to:
                import os
                filepath = os.path.join(save_to, filename)
                os.makedirs(save_to, exist_ok=True)
            else:
                filepath = filename
            all_items = [item for items in combined_results.values() for item in items if isinstance(item, dict)]
            if all_items:
                fieldnames = sorted(set().union(*(item.keys() for item in all_items)))
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(all_items)
                print(f"📊 AI audit CSV report saved: {filepath}")

    print(f"\n🎯 AI Audit Total: {total} issues (Bedrock + SageMaker)")


@click.group(name='ai')
@click.pass_context
def ai_audit(ctx):
    """AI/ML audit — Bedrock + SageMaker cost & security"""
    pass


# --- Top-level ai commands (runs both services) ---

@ai_audit.command('audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_full_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full AI audit (Bedrock + SageMaker)"""
    params = _get_ai_executor_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)
    asyncio.run(_run_combined_ai_audit(params, 'audit', output, save_to, days=days))


@ai_audit.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI cost audit (Bedrock + SageMaker)"""
    params = _get_ai_executor_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)
    asyncio.run(_run_combined_ai_audit(params, 'cost_audit', output, save_to, days=days))


@ai_audit.command('security-audit')
@common_options
@click.pass_context
def ai_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI security audit (Bedrock + SageMaker)"""
    params = _get_ai_executor_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)
    asyncio.run(_run_combined_ai_audit(params, 'security_audit', output, save_to))


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


@bedrock.command('check-model-sizing')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect premium models used for simple tasks')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_model_sizing(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect premium models used for simple tasks (requires --deep)"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_premium_model_for_simple_tasks', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, deep=deep, days=days)


@bedrock.command('check-batch-eligible')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect batch-eligible workloads')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_batch(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect On-Demand workloads eligible for Batch Inference API (requires --deep)"""
    from ..services.bedrock_audit import BedrockAuditService
    execute_service_command(ctx, BedrockAuditService, 'check_on_demand_batch_eligible', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, deep=deep, days=days)


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


@sagemaker.command('check-no-inference-components')
@common_options
@click.pass_context
def sagemaker_check_ic(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find GPU endpoints not using Inference Components (multi-model packing)"""
    from ..services.sagemaker_audit import SageMakerAuditService
    execute_service_command(ctx, SageMakerAuditService, 'check_no_inference_components', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
