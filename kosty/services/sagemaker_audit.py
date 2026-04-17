import boto3
from typing import List, Dict, Any
from datetime import datetime, timedelta


class SageMakerAuditService:
    def __init__(self):
        self.cost_checks = [
            'find_idle_endpoints', 'find_zombie_notebooks',
            'find_no_spot_training', 'find_no_checkpointing'
        ]
        self.security_checks = [
            'find_no_vpc_endpoint', 'find_notebook_direct_internet',
            'find_notebook_root_access'
        ]

    def find_idle_endpoints(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find SageMaker endpoints with zero invocations"""
        sm = session.client('sagemaker', region_name=region)
        cw = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            endpoints = sm.list_endpoints(StatusEquals='InService')
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)

            for ep in endpoints.get('Endpoints', []):
                try:
                    metrics = cw.get_metric_statistics(
                        Namespace='AWS/SageMaker', MetricName='Invocations',
                        Dimensions=[{'Name': 'EndpointName', 'Value': ep['EndpointName']}],
                        StartTime=start_time, EndTime=end_time,
                        Period=86400, Statistics=['Sum']
                    )
                    total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0

                    if total == 0:
                        detail = sm.describe_endpoint(EndpointName=ep['EndpointName'])
                        variants = detail.get('ProductionVariants', [])
                        instance_type = variants[0].get('CurrentInstanceType', 'unknown') if variants else 'unknown'
                        instance_count = variants[0].get('CurrentInstanceCount', 1) if variants else 1

                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                            'ResourceId': ep['EndpointName'], 'ResourceName': ep['EndpointName'],
                            'ARN': ep.get('EndpointArn', ''),
                            'Issue': f'Endpoint idle for {days}+ days (0 invocations)',
                            'type': 'cost',
                            'Risk': f'GPU instance {instance_type} x{instance_count} running 24/7 with no traffic',
                            'severity': 'critical', 'check': 'idle_endpoints',
                            'Details': {'InstanceType': instance_type, 'InstanceCount': instance_count}
                        })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SageMaker idle endpoints: {e}")

        return results

    def find_zombie_notebooks(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find notebook instances in InService state"""
        sm = session.client('sagemaker', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            notebooks = sm.list_notebook_instances(StatusEquals='InService')
            for nb in notebooks.get('NotebookInstances', []):
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                    'ResourceId': nb['NotebookInstanceName'], 'ResourceName': nb['NotebookInstanceName'],
                    'ARN': nb.get('NotebookInstanceArn', ''),
                    'Issue': f'Notebook instance running ({nb.get("InstanceType", "unknown")})',
                    'type': 'cost',
                    'Risk': f'~$48/mo for ml.t3.medium — running notebooks are billed even when idle',
                    'severity': 'medium', 'check': 'zombie_notebooks',
                    'Details': {'InstanceType': nb.get('InstanceType', '')}
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SageMaker notebooks: {e}")

        return results

    def find_no_spot_training(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find recent training jobs not using Spot instances"""
        sm = session.client('sagemaker', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            cutoff = datetime.utcnow() - timedelta(days=30)
            jobs = sm.list_training_jobs(
                CreationTimeAfter=cutoff,
                StatusEquals='Completed',
                SortBy='CreationTime', SortOrder='Descending',
                MaxResults=20
            )

            for job in jobs.get('TrainingJobSummaries', []):
                try:
                    detail = sm.describe_training_job(TrainingJobName=job['TrainingJobName'])
                    if not detail.get('EnableManagedSpotTraining', False):
                        duration = detail.get('TrainingTimeInSeconds', 0)
                        if duration > 3600:
                            results.append({
                                'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                                'ResourceId': job['TrainingJobName'], 'ResourceName': job['TrainingJobName'],
                                'ARN': job.get('TrainingJobArn', ''),
                                'Issue': f'Training job ran {duration // 3600}h without Spot instances',
                                'type': 'cost',
                                'Risk': 'Up to 90% savings with managed Spot training',
                                'severity': 'medium', 'check': 'no_spot_training'
                            })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SageMaker Spot training: {e}")

        return results

    def find_no_checkpointing(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Spot training jobs without checkpointing configured"""
        sm = session.client('sagemaker', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            cutoff = datetime.utcnow() - timedelta(days=30)
            jobs = sm.list_training_jobs(
                CreationTimeAfter=cutoff,
                StatusEquals='Completed',
                SortBy='CreationTime', SortOrder='Descending',
                MaxResults=20
            )

            for job in jobs.get('TrainingJobSummaries', []):
                try:
                    detail = sm.describe_training_job(TrainingJobName=job['TrainingJobName'])
                    if detail.get('EnableManagedSpotTraining', False):
                        checkpoint = detail.get('CheckpointConfig', {})
                        if not checkpoint.get('S3Uri'):
                            results.append({
                                'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                                'ResourceId': job['TrainingJobName'], 'ResourceName': job['TrainingJobName'],
                                'ARN': job.get('TrainingJobArn', ''),
                                'Issue': 'Spot training job without checkpointing',
                                'type': 'cost',
                                'Risk': 'Spot preemption loses all training progress — wasted compute spend',
                                'severity': 'high', 'check': 'no_checkpointing'
                            })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SageMaker checkpointing: {e}")

        return results

    def find_no_vpc_endpoint(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if a VPC Interface Endpoint exists for SageMaker"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            endpoints = ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.sagemaker.api']}]
            )
            if not endpoints.get('VpcEndpoints', []):
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                    'ResourceId': 'sagemaker-vpc-endpoint', 'ResourceName': 'SageMaker VPC Endpoint',
                    'Issue': 'No VPC Interface Endpoint for SageMaker API',
                    'type': 'security', 'Risk': 'SageMaker API calls traverse the public internet',
                    'severity': 'medium', 'check': 'no_vpc_endpoint'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SageMaker VPC endpoint: {e}")

        return results

    def find_notebook_direct_internet(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find notebook instances with direct internet access"""
        sm = session.client('sagemaker', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for nb in sm.list_notebook_instances().get('NotebookInstances', []):
                try:
                    detail = sm.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
                    if detail.get('DirectInternetAccess') == 'Enabled':
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                            'ResourceId': nb['NotebookInstanceName'], 'ResourceName': nb['NotebookInstanceName'],
                            'ARN': nb.get('NotebookInstanceArn', ''),
                            'Issue': 'Notebook instance has direct internet access',
                            'type': 'security', 'Risk': 'Data exfiltration path — notebook can reach any external endpoint',
                            'severity': 'high', 'check': 'notebook_direct_internet'
                        })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking notebook internet access: {e}")

        return results

    def find_notebook_root_access(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find notebook instances with root access enabled"""
        sm = session.client('sagemaker', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            for nb in sm.list_notebook_instances().get('NotebookInstances', []):
                try:
                    detail = sm.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
                    if detail.get('RootAccess') == 'Enabled':
                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'SageMaker',
                            'ResourceId': nb['NotebookInstanceName'], 'ResourceName': nb['NotebookInstanceName'],
                            'ARN': nb.get('NotebookInstanceArn', ''),
                            'Issue': 'Notebook instance has root access enabled',
                            'type': 'security', 'Risk': 'Container escape risk — root inside notebook can compromise the host',
                            'severity': 'medium', 'check': 'notebook_root_access'
                        })
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking notebook root access: {e}")

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

    def check_idle_endpoints(self, session, region, **kwargs):
        return self.find_idle_endpoints(session, region, **kwargs)

    def check_zombie_notebooks(self, session, region, **kwargs):
        return self.find_zombie_notebooks(session, region, **kwargs)

    def check_no_spot_training(self, session, region, **kwargs):
        return self.find_no_spot_training(session, region, **kwargs)

    def check_no_checkpointing(self, session, region, **kwargs):
        return self.find_no_checkpointing(session, region, **kwargs)

    def check_no_vpc_endpoint(self, session, region, **kwargs):
        return self.find_no_vpc_endpoint(session, region, **kwargs)

    def check_notebook_direct_internet(self, session, region, **kwargs):
        return self.find_notebook_direct_internet(session, region, **kwargs)

    def check_notebook_root_access(self, session, region, **kwargs):
        return self.find_notebook_root_access(session, region, **kwargs)
