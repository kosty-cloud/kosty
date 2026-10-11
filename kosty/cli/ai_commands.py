import click
import json
import os
from pathlib import Path
from datetime import datetime
from .utils import common_options, execute_engine_command, _ensure_plugins_loaded, _resolve_scan_params


def _run_combined_ai_audit(ctx, method, output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, **kwargs):
    """Run Bedrock + SageMaker via engine, merge results, output once."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from ..core.registry import registry
    from ..core.models import FindingType

    session, reg_list, workers, config_manager = _resolve_scan_params(
        ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id
    )

    _ensure_plugins_loaded()

    finding_type_filter = None
    if method == 'cost_audit':
        finding_type_filter = FindingType.COST
    elif method == 'security_audit':
        finding_type_filter = FindingType.SECURITY

    deep = kwargs.get('deep', False)

    all_findings = []
    for service_name in ['Bedrock', 'SageMaker']:
        checks = registry.get_checks_by_service(service_name)
        if finding_type_filter:
            checks = [c for c in checks if c['metadata'].finding_type == finding_type_filter]
        if not deep:
            checks = [c for c in checks if not c['metadata'].requires_deep]

        svc_findings = []
        for rgn in reg_list:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(c['func'], session=session, region=rgn, config_manager=config_manager, **kwargs): c for c in checks}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if isinstance(result, list):
                            svc_findings.extend(result)
                    except Exception:
                        pass

        print(f"\n🤖 {service_name} Audit: {len(svc_findings)} issues")
        all_findings.extend(svc_findings)

    total = len(all_findings)
    items = [f.to_dict() for f in all_findings]

    verbose = ctx.obj.get('verbose', False) if ctx.obj else False

    if output in ['console', 'all']:
        if total > 0:
            print(f"\n{'─' * 50}")
            for item in items:
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(item.get('severity', ''), '⚪')
                print(f"  {sev_icon} [{item.get('Service')}] {item.get('Issue')}")
                print(f"     Resource: {item.get('ResourceId', '')} ({item.get('Region', '')})")
                if verbose:
                    if item.get('Risk'):
                        print(f"     Risk: {item['Risk']}")
                    if item.get('ARN'):
                        print(f"     ARN: {item['ARN']}")
                    savings = item.get('monthly_savings') or item.get('MonthlySavings')
                    if savings:
                        print(f"     Savings: ${savings:.2f}/mo")
                    if item.get('check'):
                        print(f"     Check: {item['check']}")
    if output in ['json', 'all']:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_ai_{account_id}_{timestamp}.json"
        if save_to:
            dest = Path(save_to).resolve()
            dest.mkdir(parents=True, exist_ok=True)
            filename = str(dest / filename)
        report = {'scan_timestamp': datetime.now().isoformat(), 'method': f'ai_{method}', 'total_issues': total, 'results': {account_id: items}}
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 AI audit JSON report saved: {filename}")

    if output in ['csv', 'all']:
        import csv
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_ai_{account_id}_{timestamp}.csv"
        if save_to:
            dest = Path(save_to).resolve()
            dest.mkdir(parents=True, exist_ok=True)
            filename = str(dest / filename)
        if items:
            fieldnames = sorted(set().union(*(item.keys() for item in items)))
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(items)
            print(f"📊 AI audit CSV report saved: {filename}")

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
    _run_combined_ai_audit(ctx, 'audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, days=days)


@ai_audit.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI cost audit (Bedrock + SageMaker)"""
    _run_combined_ai_audit(ctx, 'cost_audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, days=days)


@ai_audit.command('security-audit')
@common_options
@click.pass_context
def ai_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI security audit (Bedrock + SageMaker)"""
    _run_combined_ai_audit(ctx, 'security_audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)


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
    execute_engine_command(ctx, 'Bedrock', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('cost-audit')
@common_options
@click.pass_context
def bedrock_cost(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock cost audit"""
    execute_engine_command(ctx, 'Bedrock', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('security-audit')
@common_options
@click.pass_context
def bedrock_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock security audit"""
    execute_engine_command(ctx, 'Bedrock', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-logging')
@common_options
@click.pass_context
def bedrock_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock invocation logging is enabled"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-001')


@bedrock.command('check-no-budget-limits')
@common_options
@click.pass_context
def bedrock_check_budget(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if AWS Budget exists for Bedrock spend"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-002')


@bedrock.command('check-no-guardrails')
@common_options
@click.pass_context
def bedrock_check_guardrails(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock Guardrails are configured"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-003')


@bedrock.command('check-shadow-ai')
@common_options
@click.pass_context
def bedrock_check_shadow(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find IAM roles with AI permissions not tagged as approved"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-004')


@bedrock.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def bedrock_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for Bedrock"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-005')


@bedrock.command('check-custom-model-no-kms')
@common_options
@click.pass_context
def bedrock_check_kms(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if custom models are encrypted with customer-managed KMS"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-006')


@bedrock.command('check-no-prompt-caching')
@common_options
@click.pass_context
def bedrock_check_caching(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if prompt caching is being used"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-007')


@bedrock.command('check-no-inference-profiles')
@common_options
@click.pass_context
def bedrock_check_profiles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Application Inference Profiles are configured"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-008')


@bedrock.command('check-tpm-quota')
@common_options
@click.pass_context
def bedrock_check_tpm(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock TPM quota usage is above 80%"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-009')


@bedrock.command('check-cross-account-model-access')
@common_options
@click.pass_context
def bedrock_check_cross_account(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check S3 bucket policies on custom model training data for cross-account access"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-010')


@bedrock.command('check-model-sizing')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect premium models used for simple tasks')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_model_sizing(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect premium models used for simple tasks (requires --deep)"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-011', deep=deep, days=days)


@bedrock.command('check-batch-eligible')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect batch-eligible workloads')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_batch(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect On-Demand workloads eligible for Batch Inference API (requires --deep)"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-012', deep=deep, days=days)


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
    execute_engine_command(ctx, 'SageMaker', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_cost(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker cost audit"""
    execute_engine_command(ctx, 'SageMaker', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('security-audit')
@common_options
@click.pass_context
def sagemaker_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker security audit"""
    execute_engine_command(ctx, 'SageMaker', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-idle-endpoints')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_check_idle(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find endpoints with zero invocations"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-001', days=days)


@sagemaker.command('check-zombie-notebooks')
@common_options
@click.pass_context
def sagemaker_check_notebooks(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find running notebook instances"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-002')


@sagemaker.command('check-no-spot-training')
@common_options
@click.pass_context
def sagemaker_check_spot(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find training jobs not using Spot instances"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-003')


@sagemaker.command('check-no-checkpointing')
@common_options
@click.pass_context
def sagemaker_check_checkpoint(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Spot training jobs without checkpointing"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-004')


@sagemaker.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def sagemaker_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for SageMaker"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-005')


@sagemaker.command('check-notebook-direct-internet')
@common_options
@click.pass_context
def sagemaker_check_internet(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with direct internet access"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-006')


@sagemaker.command('check-notebook-root-access')
@common_options
@click.pass_context
def sagemaker_check_root(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with root access enabled"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-007')


@sagemaker.command('check-no-inference-components')
@common_options
@click.pass_context
def sagemaker_check_ic(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find GPU endpoints not using Inference Components (multi-model packing)"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-008')
