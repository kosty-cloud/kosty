import boto3
import json
from typing import List, Dict, Any
from datetime import datetime, timedelta


class BedrockAuditService:
    def __init__(self):
        self.cost_checks = ['find_no_budget_limits', 'find_no_prompt_caching', 'find_no_inference_profiles', 'find_tpm_quota_high_usage', 'find_premium_model_for_simple_tasks', 'find_on_demand_batch_eligible']
        self.security_checks = [
            'find_no_logging', 'find_no_guardrails', 'find_shadow_ai',
            'find_no_vpc_endpoint', 'find_custom_model_no_kms',
            'find_cross_account_model_access'
        ]

    def find_no_logging(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if Bedrock model invocation logging is enabled"""
        bedrock = session.client('bedrock', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            config = bedrock.get_model_invocation_logging_configuration()
            logging_config = config.get('loggingConfig', {})

            has_s3 = bool(logging_config.get('s3Config', {}).get('bucketName'))
            has_cw = bool(logging_config.get('cloudWatchConfig', {}).get('logGroupName'))

            if not has_s3 and not has_cw:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-logging', 'ResourceName': 'Bedrock Logging',
                    'Issue': 'Bedrock model invocation logging not enabled',
                    'type': 'security', 'Risk': 'No audit trail on GenAI usage — prompt injection and data leakage go undetected',
                    'severity': 'high', 'check': 'no_logging'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock logging: {e}")

        return results

    def find_no_budget_limits(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if AWS Budgets exist for Bedrock spend"""
        budgets = session.client('budgets', region_name='us-east-1')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            resp = budgets.describe_budgets(AccountId=account_id)
            budget_list = resp.get('Budgets', [])

            has_bedrock_budget = any(
                'bedrock' in b.get('BudgetName', '').lower() or
                any('bedrock' in str(f).lower() for f in b.get('CostFilters', {}).values())
                for b in budget_list
            )

            if not has_bedrock_budget:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-budget', 'ResourceName': 'Bedrock Budget',
                    'Issue': 'No AWS Budget configured for Bedrock spend',
                    'type': 'cost', 'Risk': 'Stolen API key or runaway automation = unlimited GenAI spend with no alert',
                    'severity': 'high', 'check': 'no_budget_limits'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock budgets: {e}")

        return results

    def find_no_guardrails(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if Bedrock Guardrails are configured"""
        bedrock = session.client('bedrock', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            guardrails = bedrock.list_guardrails()
            if not guardrails.get('guardrails', []):
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-guardrails', 'ResourceName': 'Bedrock Guardrails',
                    'Issue': 'No Bedrock Guardrails configured',
                    'type': 'security', 'Risk': 'No protection against prompt injection, PII leakage, or toxic content in model responses',
                    'severity': 'high', 'check': 'no_guardrails'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock Guardrails: {e}")

        return results

    def find_shadow_ai(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find IAM roles with bedrock:* or sagemaker:* not tagged as approved AI project"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for role in iam.list_roles()['Roles']:
                if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                    continue

                has_ai_perms = False
                try:
                    for p in iam.list_attached_role_policies(RoleName=role['RoleName']).get('AttachedPolicies', []):
                        if any(svc in p['PolicyName'].lower() for svc in ['bedrock', 'sagemaker']):
                            has_ai_perms = True
                            break

                    if not has_ai_perms:
                        for pname in iam.list_role_policies(RoleName=role['RoleName']).get('PolicyNames', []):
                            doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=pname)['PolicyDocument']
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            for stmt in doc.get('Statement', []):
                                actions = stmt.get('Action', [])
                                if not isinstance(actions, list):
                                    actions = [actions]
                                if any('bedrock' in a.lower() or 'sagemaker' in a.lower() for a in actions):
                                    has_ai_perms = True
                                    break
                except Exception:
                    continue

                if not has_ai_perms:
                    continue

                tags = {t['Key']: t['Value'] for t in iam.list_role_tags(RoleName=role['RoleName']).get('Tags', [])}
                is_approved = any(k.lower() in ['ai-project', 'ai_project', 'ml-project', 'ml_project', 'genai'] for k in tags)

                if not is_approved:
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                        'ResourceId': role['RoleName'], 'ResourceName': role['RoleName'],
                        'ARN': role['Arn'],
                        'Issue': 'IAM role with AI/ML permissions not tagged as approved project',
                        'type': 'security', 'Risk': 'Potential shadow AI usage — untracked GenAI spend and data exposure',
                        'severity': 'medium', 'check': 'shadow_ai'
                    })
        except Exception as e:
            print(f"Error checking shadow AI: {e}")

        return results

    def find_no_vpc_endpoint(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if a VPC Interface Endpoint exists for Bedrock"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            endpoints = ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.bedrock-runtime']}]
            )
            if not endpoints.get('VpcEndpoints', []):
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-vpc-endpoint', 'ResourceName': 'Bedrock VPC Endpoint',
                    'Issue': 'No VPC Interface Endpoint for Bedrock runtime',
                    'type': 'security', 'Risk': 'Model invocations traverse the public internet instead of staying within the VPC',
                    'severity': 'medium', 'check': 'no_vpc_endpoint'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock VPC endpoint: {e}")

        return results

    def find_custom_model_no_kms(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if custom models are encrypted with customer-managed KMS keys"""
        bedrock = session.client('bedrock', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            models = bedrock.list_custom_models()
            for model in models.get('modelSummaries', []):
                try:
                    detail = bedrock.get_custom_model(modelIdentifier=model['modelName'])
                    kms_key = detail.get('customModelKmsKeyId', '')
                    if not kms_key:
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                            'ResourceId': model['modelName'], 'ResourceName': model['modelName'],
                            'ARN': model.get('modelArn', ''),
                            'Issue': 'Custom model not encrypted with customer-managed KMS key',
                            'type': 'security', 'Risk': 'Model artifacts encrypted with AWS-managed key only — less control over key lifecycle',
                            'severity': 'medium', 'check': 'custom_model_no_kms'
                        })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking custom model encryption: {e}")

        return results

    def find_no_prompt_caching(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Flag if prompt caching is available but not being used"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            bedrock = session.client('bedrock', region_name=region)
            # Check if any inference profiles exist — if models are used but no caching config, flag it
            models = bedrock.list_foundation_models()
            cache_compatible = [m for m in models.get('modelSummaries', [])
                               if 'anthropic' in m.get('providerName', '').lower()
                               or 'amazon' in m.get('providerName', '').lower()]

            if cache_compatible:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'prompt-caching', 'ResourceName': 'Prompt Caching',
                    'Issue': f'{len(cache_compatible)} cache-compatible models available — verify prompt caching is enabled in your application',
                    'type': 'cost', 'Risk': 'Up to 90% savings on repeated system prompts and RAG contexts if caching is enabled',
                    'severity': 'medium', 'check': 'no_prompt_caching'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking prompt caching: {e}")

        return results

    def find_no_inference_profiles(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if Application Inference Profiles are configured for cost attribution"""
        bedrock = session.client('bedrock', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            profiles = bedrock.list_inference_profiles()
            if not profiles.get('inferenceProfileSummaries', []):
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'inference-profiles', 'ResourceName': 'Inference Profiles',
                    'Issue': 'No Application Inference Profiles configured',
                    'type': 'cost', 'Risk': 'Cannot attribute token spend per team or project — no chargeback possible',
                    'severity': 'low', 'check': 'no_inference_profiles'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e) and 'ValidationException' not in str(e):
                print(f"Error checking inference profiles: {e}")

        return results

    def find_tpm_quota_high_usage(self, session: boto3.Session, region: str, threshold: int = 80, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if Bedrock TPM quota usage is above threshold"""
        sq = session.client('service-quotas', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = sq.get_paginator('list_service_quotas')
            for page in paginator.paginate(ServiceCode='bedrock'):
                for quota in page['Quotas']:
                    if 'token' not in quota.get('QuotaName', '').lower():
                        continue

                    quota_value = quota.get('Value', 0)
                    if quota_value == 0:
                        continue

                    usage = quota.get('UsageMetric', {})
                    if not usage:
                        continue

                    try:
                        cw = session.client('cloudwatch', region_name=region)
                        metrics = cw.get_metric_statistics(
                            Namespace=usage.get('MetricNamespace', ''),
                            MetricName=usage.get('MetricName', ''),
                            Dimensions=[{'Name': k, 'Value': v} for k, v in usage.get('MetricDimensions', {}).items()],
                            StartTime=datetime.utcnow() - timedelta(hours=24),
                            EndTime=datetime.utcnow(),
                            Period=3600, Statistics=['Maximum']
                        )
                        if metrics['Datapoints']:
                            max_usage = max(dp['Maximum'] for dp in metrics['Datapoints'])
                            pct = (max_usage / quota_value) * 100
                            if pct >= threshold:
                                results.append({
                                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                                    'ResourceId': quota['QuotaName'], 'ResourceName': quota['QuotaName'],
                                    'Issue': f'TPM quota at {round(pct)}% ({round(max_usage)}/{round(quota_value)})',
                                    'type': 'cost',
                                    'Risk': 'Approaching throttling limit — production requests will be rejected',
                                    'severity': 'high' if pct >= 90 else 'medium',
                                    'check': 'tpm_quota_high_usage'
                                })
                    except Exception:
                        continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock TPM quotas: {e}")

        return results

    def find_cross_account_model_access(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check S3 bucket policies on custom model training data for cross-account access"""
        bedrock = session.client('bedrock', region_name=region)
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            models = bedrock.list_custom_models()
            checked_buckets = set()

            for model in models.get('modelSummaries', []):
                try:
                    detail = bedrock.get_custom_model(modelIdentifier=model['modelName'])
                    s3_uri = detail.get('trainingDataConfig', {}).get('s3Uri', '')
                    if not s3_uri or not s3_uri.startswith('s3://'):
                        continue

                    bucket = s3_uri.split('/')[2]
                    if bucket in checked_buckets:
                        continue
                    checked_buckets.add(bucket)

                    try:
                        policy_str = s3.get_bucket_policy(Bucket=bucket)['Policy']
                        policy = json.loads(policy_str)

                        for stmt in policy.get('Statement', []):
                            if stmt.get('Effect') != 'Allow':
                                continue
                            principal = stmt.get('Principal', {})
                            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                results.append({
                                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                                    'ResourceId': bucket, 'ResourceName': f'{model["modelName"]} ({bucket})',
                                    'Issue': f'Training data bucket "{bucket}" has wildcard principal in policy',
                                    'type': 'security',
                                    'Risk': 'Unauthorized third-party access to model training data',
                                    'severity': 'high', 'check': 'cross_account_model_access'
                                })
                                break

                            if isinstance(principal, dict):
                                aws_principals = principal.get('AWS', [])
                                if not isinstance(aws_principals, list):
                                    aws_principals = [aws_principals]
                                for p in aws_principals:
                                    if ':' in str(p) and account_id not in str(p):
                                        results.append({
                                            'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                                            'ResourceId': bucket, 'ResourceName': f'{model["modelName"]} ({bucket})',
                                            'Issue': f'Training data bucket "{bucket}" grants cross-account access',
                                            'type': 'security',
                                            'Risk': 'External account can read model training data',
                                            'severity': 'medium', 'check': 'cross_account_model_access'
                                        })
                                        break
                    except s3.exceptions.from_code('NoSuchBucketPolicy'):
                        pass
                    except Exception:
                        continue
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking cross-account model access: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results

    def check_no_logging(self, session, region, **kwargs):
        return self.find_no_logging(session, region, **kwargs)

    def check_no_budget_limits(self, session, region, **kwargs):
        return self.find_no_budget_limits(session, region, **kwargs)

    def check_no_guardrails(self, session, region, **kwargs):
        return self.find_no_guardrails(session, region, **kwargs)

    def check_shadow_ai(self, session, region, **kwargs):
        return self.find_shadow_ai(session, region, **kwargs)

    def check_no_vpc_endpoint(self, session, region, **kwargs):
        return self.find_no_vpc_endpoint(session, region, **kwargs)

    def check_custom_model_no_kms(self, session, region, **kwargs):
        return self.find_custom_model_no_kms(session, region, **kwargs)

    def check_no_prompt_caching(self, session, region, **kwargs):
        return self.find_no_prompt_caching(session, region, **kwargs)

    def check_no_inference_profiles(self, session, region, **kwargs):
        return self.find_no_inference_profiles(session, region, **kwargs)

    def check_tpm_quota_high_usage(self, session, region, **kwargs):
        return self.find_tpm_quota_high_usage(session, region, **kwargs)

    def check_cross_account_model_access(self, session, region, **kwargs):
        return self.find_cross_account_model_access(session, region, **kwargs)

    def find_premium_model_for_simple_tasks(self, session: boto3.Session, region: str, days: int = 7, deep: bool = False, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Flag premium models used for simple tasks based on token usage patterns"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        if config_manager:
            days = config_manager.get_threshold('bedrock_log_days', days)

        if not deep:
            results.append({
                'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                'ResourceId': 'model-sizing', 'ResourceName': 'Model Sizing Check',
                'Issue': 'Run with --deep to analyze model usage patterns from CloudWatch Logs',
                'type': 'cost', 'Risk': 'Up to 30% savings by routing simple tasks to lighter models',
                'severity': 'info', 'check': 'premium_model_for_simple_tasks'
            })
            return results

        try:
            logs = session.client('logs', region_name=region)
            bedrock = session.client('bedrock', region_name=region)

            config = bedrock.get_model_invocation_logging_configuration()
            log_group = config.get('loggingConfig', {}).get('cloudWatchConfig', {}).get('logGroupName', '')
            if not log_group:
                return results

            end_time = int(datetime.utcnow().timestamp() * 1000)
            start_time = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)

            premium_models = ['claude-3-5-sonnet', 'claude-3-opus', 'claude-3-sonnet']

            query = logs.start_query(
                logGroupName=log_group,
                startTime=start_time, endTime=end_time,
                queryString="""
                    fields @timestamp, modelId, input.inputTokenCount, output.outputTokenCount
                    | filter ispresent(modelId)
                    | stats avg(input.inputTokenCount) as avgInput, avg(output.outputTokenCount) as avgOutput, count() as invocations by modelId
                    | sort invocations desc
                    | limit 20
                """
            )

            import time
            query_id = query['queryId']
            for _ in range(30):
                time.sleep(1)
                result = logs.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    break

            for row in result.get('results', []):
                row_dict = {f['field']: f['value'] for f in row}
                model_id = row_dict.get('modelId', '').lower()
                avg_input = float(row_dict.get('avgInput', 0) or 0)
                avg_output = float(row_dict.get('avgOutput', 0) or 0)
                invocations = int(row_dict.get('invocations', 0) or 0)

                is_premium = any(m in model_id for m in premium_models)
                is_simple = avg_input < 500 and avg_output < 150

                if is_premium and is_simple and invocations > 100:
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                        'ResourceId': model_id, 'ResourceName': model_id,
                        'Issue': f'Premium model used for simple tasks (avg {round(avg_input)} input / {round(avg_output)} output tokens, {invocations} invocations)',
                        'type': 'cost',
                        'Risk': 'Consider routing to Claude Haiku or Titan Lite — up to 30% savings',
                        'severity': 'medium', 'check': 'premium_model_for_simple_tasks',
                        'Details': {
                            'AvgInputTokens': round(avg_input),
                            'AvgOutputTokens': round(avg_output),
                            'Invocations': invocations,
                            'Note': 'Heuristic analysis — verify before acting'
                        }
                    })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking model sizing: {e}")

        return results

    def find_on_demand_batch_eligible(self, session: boto3.Session, region: str, days: int = 7, deep: bool = False, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Detect On-Demand workloads that could use Batch Inference API (50% cheaper)"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        if config_manager:
            days = config_manager.get_threshold('bedrock_log_days', days)

        if not deep:
            results.append({
                'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                'ResourceId': 'batch-inference', 'ResourceName': 'Batch Inference Check',
                'Issue': 'Run with --deep to analyze invocation patterns for batch eligibility',
                'type': 'cost', 'Risk': '50% savings by switching burst workloads to Batch Inference API',
                'severity': 'info', 'check': 'on_demand_batch_eligible'
            })
            return results

        try:
            logs = session.client('logs', region_name=region)
            bedrock = session.client('bedrock', region_name=region)

            config = bedrock.get_model_invocation_logging_configuration()
            log_group = config.get('loggingConfig', {}).get('cloudWatchConfig', {}).get('logGroupName', '')
            if not log_group:
                return results

            end_time = int(datetime.utcnow().timestamp() * 1000)
            start_time = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)

            query = logs.start_query(
                logGroupName=log_group,
                startTime=start_time, endTime=end_time,
                queryString="""
                    fields @timestamp, modelId
                    | filter ispresent(modelId)
                    | stats count() as invocations by modelId, datefloor(@timestamp, 1h) as hour
                    | stats max(invocations) as peakHour, min(invocations) as quietHour, avg(invocations) as avgHour by modelId
                    | filter peakHour > avgHour * 5
                    | sort peakHour desc
                    | limit 10
                """
            )

            import time
            query_id = query['queryId']
            for _ in range(30):
                time.sleep(1)
                result = logs.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    break

            for row in result.get('results', []):
                row_dict = {f['field']: f['value'] for f in row}
                model_id = row_dict.get('modelId', '')
                peak = int(row_dict.get('peakHour', 0) or 0)
                avg = float(row_dict.get('avgHour', 0) or 0)

                if peak > 50 and avg > 0:
                    results.append({
                        'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                        'ResourceId': model_id, 'ResourceName': model_id,
                        'Issue': f'Burst invocation pattern detected ({peak} req/h peak vs {round(avg)} avg) — batch-eligible',
                        'type': 'cost',
                        'Risk': 'Batch Inference API is 50% cheaper for non-real-time workloads',
                        'severity': 'medium', 'check': 'on_demand_batch_eligible',
                        'Details': {
                            'PeakInvocationsPerHour': peak,
                            'AvgInvocationsPerHour': round(avg),
                            'Note': 'Heuristic analysis — verify workload is non-real-time before switching'
                        }
                    })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking batch eligibility: {e}")

        return results

    def check_premium_model_for_simple_tasks(self, session, region, **kwargs):
        return self.find_premium_model_for_simple_tasks(session, region, **kwargs)

    def check_on_demand_batch_eligible(self, session, region, **kwargs):
        return self.find_on_demand_batch_eligible(session, region, **kwargs)
