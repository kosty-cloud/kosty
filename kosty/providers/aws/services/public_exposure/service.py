import boto3
from typing import List, Dict, Any
import json


class PublicExposureService:
    """Scans all services for public-facing resources and evaluates their protection level"""

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run full public exposure audit"""
        results = []
        results.extend(self._check_load_balancers(session, region))
        results.extend(self._check_ec2_public_ips(session, region))
        results.extend(self._check_s3_public(session, region))
        results.extend(self._check_rds_public(session, region))
        results.extend(self._check_rds_snapshots_public(session, region))
        results.extend(self._check_ebs_snapshots_public(session, region))
        results.extend(self._check_apigateway(session, region))
        results.extend(self._check_lambda_urls(session, region))
        results.extend(self._check_cloudfront(session, region))
        results.extend(self._check_opensearch(session, region))
        results.extend(self._check_redshift(session, region))
        results.extend(self._check_eks(session, region))
        results.extend(self._check_ecr_public(session, region))
        results.extend(self._check_sns_public(session, region))
        results.extend(self._check_sqs_public(session, region))
        return results

    def _get_account_id(self, session: boto3.Session) -> str:
        return session.client('sts').get_caller_identity()['Account']

    def _get_waf_acl_resource_arns(self, session: boto3.Session, region: str) -> set:
        """Collect all resource ARNs protected by WAF"""
        protected = set()
        try:
            waf = session.client('wafv2', region_name=region)
            for scope in ['REGIONAL']:
                acls = waf.list_web_acls(Scope=scope)
                for acl in acls.get('WebACLs', []):
                    for res_type in ['APPLICATION_LOAD_BALANCER', 'API_GATEWAY']:
                        try:
                            resp = waf.list_resources_for_web_acl(WebACLArn=acl['ARN'], ResourceType=res_type)
                            protected.update(resp.get('ResourceArns', []))
                        except Exception:
                            continue
        except Exception:
            pass
        return protected

    def _classify(self, protections: List[str]) -> dict:
        """Classify exposure level based on protections found"""
        if not protections:
            return {'level': 'critical', 'label': 'Exposed & Unprotected', 'emoji': '🔴'}
        all_good = all(p.endswith('✓') for p in protections)
        if all_good:
            return {'level': 'info', 'label': 'Exposed & Protected', 'emoji': '🟢'}
        return {'level': 'high', 'label': 'Exposed & Partially Protected', 'emoji': '🟡'}

    def _build_finding(self, account_id, region, resource_id, resource_type, protections, details=None):
        classification = self._classify(protections)
        
        prot_pass = [p for p in protections if p.endswith('✓')]
        prot_fail = [p for p in protections if p.endswith('✗')]
        
        protection_summary = ''
        if prot_fail:
            protection_summary += f" | Missing: {', '.join(prot_fail)}"
        if prot_pass:
            protection_summary += f" | OK: {', '.join(prot_pass)}"
        
        return {
            'AccountId': account_id,
            'Region': region,
            'Service': 'PublicExposure',
            'ResourceId': resource_id,
            'ResourceName': resource_id,
            'ResourceType': resource_type,
            'Issue': f"{classification['emoji']} {resource_type} [{classification['label']}]{protection_summary}",
            'type': 'security',
            'Risk': f"Internet-facing {resource_type} — {', '.join(protections) if protections else 'NO protections detected'}",
            'severity': classification['level'],
            'check': 'public_exposure',
            'Protections': protections,
            'ExposureLevel': classification['label'],
            'Details': details or {}
        }

    # --- Load Balancers ---
    def _check_load_balancers(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            elb = session.client('elbv2', region_name=region)
            account_id = self._get_account_id(session)
            waf_protected = self._get_waf_acl_resource_arns(session, region)

            for lb in elb.describe_load_balancers()['LoadBalancers']:
                if lb.get('Scheme') != 'internet-facing':
                    continue

                protections = []
                if lb['LoadBalancerArn'] in waf_protected:
                    protections.append('WAF ✓')
                else:
                    protections.append('WAF ✗')

                # Check listeners for HTTPS
                listeners = elb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                has_https = any(l.get('Protocol') == 'HTTPS' for l in listeners['Listeners'])
                protections.append('HTTPS ✓' if has_https else 'HTTPS ✗')

                results.append(self._build_finding(
                    account_id, region, lb['LoadBalancerName'], 'ALB/NLB', protections,
                    {'DNSName': lb.get('DNSName'), 'Type': lb.get('Type'), 'ARN': lb['LoadBalancerArn']}
                ))
        except Exception as e:
            print(f"Error checking public load balancers: {e}")
        return results

    # --- EC2 Public IPs ---
    def _check_ec2_public_ips(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            ec2 = session.client('ec2', region_name=region)
            account_id = self._get_account_id(session)

            instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            for res in instances['Reservations']:
                for inst in res['Instances']:
                    public_ip = inst.get('PublicIpAddress')
                    if not public_ip:
                        continue

                    protections = []
                    open_ports = set()
                    for sg in inst.get('SecurityGroups', []):
                        try:
                            sg_detail = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                            for rule in sg_detail['SecurityGroups'][0].get('IpPermissions', []):
                                if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                                    from_port = rule.get('FromPort', 0)
                                    to_port = rule.get('ToPort', 0)
                                    if from_port and to_port:
                                        open_ports.update(range(from_port, to_port + 1))
                        except Exception:
                            continue

                    only_web = open_ports.issubset({80, 443, 8080, 8443})
                    if only_web and open_ports:
                        protections.append('SG web-only ✓')
                    elif open_ports:
                        protections.append(f'SG open ports: {sorted(open_ports)[:5]} ✗')

                    imds = inst.get('MetadataOptions', {}).get('HttpTokens', 'optional')
                    protections.append('IMDSv2 ✓' if imds == 'required' else 'IMDSv2 ✗')

                    results.append(self._build_finding(
                        account_id, region, inst['InstanceId'], 'EC2', protections,
                        {'PublicIP': public_ip, 'InstanceType': inst['InstanceType']}
                    ))
        except Exception as e:
            print(f"Error checking EC2 public IPs: {e}")
        return results

    # --- S3 Public ---
    def _check_s3_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            s3 = session.client('s3')
            s3control = session.client('s3control', region_name=region)
            account_id = self._get_account_id(session)

            # Check account-level public access block
            account_block = True
            try:
                pab = s3control.get_public_access_block(AccountId=account_id)
                config = pab['PublicAccessBlockConfiguration']
                account_block = all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ])
            except Exception:
                account_block = False

            for bucket in s3.list_buckets()['Buckets']:
                bucket_name = bucket['Name']
                is_public = False
                protections = []

                try:
                    # Check bucket-level public access block
                    try:
                        bpab = s3.get_public_access_block(Bucket=bucket_name)
                        config = bpab['PublicAccessBlockConfiguration']
                        bucket_blocked = all([
                            config.get('BlockPublicAcls', False),
                            config.get('IgnorePublicAcls', False),
                            config.get('BlockPublicPolicy', False),
                            config.get('RestrictPublicBuckets', False)
                        ])
                        if bucket_blocked:
                            continue
                    except Exception:
                        pass

                    # Check ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        uri = grant.get('Grantee', {}).get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            is_public = True
                            break

                    # Check policy
                    if not is_public:
                        try:
                            policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)['Policy'])
                            for stmt in policy.get('Statement', []):
                                if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ['*', {'AWS': '*'}]:
                                    is_public = True
                                    break
                        except Exception:
                            pass

                    if not is_public:
                        continue

                    if account_block:
                        protections.append('Account PublicAccessBlock ✓')
                    else:
                        protections.append('Account PublicAccessBlock ✗')

                    # Check if CloudFront is in front
                    try:
                        cf = session.client('cloudfront')
                        dists = cf.list_distributions()
                        has_cf = False
                        if 'DistributionList' in dists and 'Items' in dists['DistributionList']:
                            for dist in dists['DistributionList']['Items']:
                                for origin in dist.get('Origins', {}).get('Items', []):
                                    if bucket_name in origin.get('DomainName', ''):
                                        has_cf = True
                                        break
                        protections.append('CloudFront ✓' if has_cf else 'CloudFront ✗')
                    except Exception:
                        pass

                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'

                    results.append(self._build_finding(
                        account_id, bucket_region, bucket_name, 'S3', protections
                    ))
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking S3 public exposure: {e}")
        return results

    # --- RDS Public ---
    def _check_rds_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            rds = session.client('rds', region_name=region)
            ec2 = session.client('ec2', region_name=region)
            account_id = self._get_account_id(session)

            for db in rds.describe_db_instances()['DBInstances']:
                if not db.get('PubliclyAccessible', False):
                    continue

                protections = []
                for sg in db.get('VpcSecurityGroups', []):
                    try:
                        sg_detail = ec2.describe_security_groups(GroupIds=[sg['VpcSecurityGroupId']])
                        for rule in sg_detail['SecurityGroups'][0].get('IpPermissions', []):
                            if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                                protections.append(f'SG {sg["VpcSecurityGroupId"]} open to 0.0.0.0/0 ✗')
                            else:
                                protections.append(f'SG {sg["VpcSecurityGroupId"]} restricted ✓')
                    except Exception:
                        continue

                protections.append('Encrypted ✓' if db.get('StorageEncrypted') else 'Encrypted ✗')

                results.append(self._build_finding(
                    account_id, region, db['DBInstanceIdentifier'], 'RDS', protections,
                    {'Engine': db['Engine'], 'InstanceClass': db['DBInstanceClass']}
                ))
        except Exception as e:
            print(f"Error checking RDS public exposure: {e}")
        return results

    # --- RDS Snapshots Public ---
    def _check_rds_snapshots_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            rds = session.client('rds', region_name=region)
            account_id = self._get_account_id(session)

            for snap in rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']:
                try:
                    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap['DBSnapshotIdentifier'])
                    for attr in attrs['DBSnapshotAttributesResult'].get('DBSnapshotAttributes', []):
                        if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                            results.append(self._build_finding(
                                account_id, region, snap['DBSnapshotIdentifier'], 'RDS Snapshot', [],
                                {'Engine': snap.get('Engine'), 'SnapshotCreateTime': str(snap.get('SnapshotCreateTime', ''))}
                            ))
                            break
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking RDS public snapshots: {e}")
        return results

    # --- EBS Snapshots Public ---
    def _check_ebs_snapshots_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            ec2 = session.client('ec2', region_name=region)
            account_id = self._get_account_id(session)

            for snap in ec2.describe_snapshots(OwnerIds=[account_id])['Snapshots']:
                try:
                    attrs = ec2.describe_snapshot_attribute(SnapshotId=snap['SnapshotId'], Attribute='createVolumePermission')
                    if any(p.get('Group') == 'all' for p in attrs.get('CreateVolumePermissions', [])):
                        results.append(self._build_finding(
                            account_id, region, snap['SnapshotId'], 'EBS Snapshot', [],
                            {'VolumeSize': snap['VolumeSize'], 'Encrypted': snap.get('Encrypted', False)}
                        ))
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking EBS public snapshots: {e}")
        return results

    # --- API Gateway ---
    def _check_apigateway(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            apigw = session.client('apigateway', region_name=region)
            account_id = self._get_account_id(session)
            waf_protected = self._get_waf_acl_resource_arns(session, region)

            for api in apigw.get_rest_apis().get('items', []):
                endpoint_types = api.get('endpointConfiguration', {}).get('types', [])
                if 'PRIVATE' in endpoint_types:
                    continue

                protections = []
                stages = apigw.get_stages(restApiId=api['id'])
                for stage in stages.get('item', []):
                    stage_arn = f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    has_waf = stage.get('webAclArn', '') or stage_arn in waf_protected
                    protections.append(f"WAF ({stage['stageName']}) {'✓' if has_waf else '✗'}")

                    settings = stage.get('methodSettings', {}).get('*/*', {})
                    rate = settings.get('throttlingRateLimit', 0)
                    protections.append(f"Throttling ({stage['stageName']}) {'✓' if rate and rate < 10000 else '✗'}")

                # Check auth on methods
                has_unauth = False
                try:
                    resources = apigw.get_resources(restApiId=api['id'])
                    for res in resources.get('items', []):
                        for method_name in res.get('resourceMethods', {}):
                            try:
                                method = apigw.get_method(restApiId=api['id'], resourceId=res['id'], httpMethod=method_name)
                                if method.get('authorizationType') == 'NONE':
                                    has_unauth = True
                                    break
                            except Exception:
                                continue
                        if has_unauth:
                            break
                except Exception:
                    pass
                protections.append('Auth ✓' if not has_unauth else 'Auth ✗ (NONE endpoints)')

                results.append(self._build_finding(
                    account_id, region, api['name'], 'API Gateway', protections,
                    {'ApiId': api['id'], 'EndpointType': endpoint_types}
                ))
        except Exception as e:
            print(f"Error checking API Gateway exposure: {e}")
        return results

    # --- Lambda Function URLs ---
    def _check_lambda_urls(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            lam = session.client('lambda', region_name=region)
            account_id = self._get_account_id(session)

            for func in lam.list_functions()['Functions']:
                try:
                    url_config = lam.get_function_url_config(FunctionName=func['FunctionName'])
                    protections = []
                    auth_type = url_config.get('AuthType', 'NONE')
                    protections.append(f'Auth {auth_type} {"✓" if auth_type == "AWS_IAM" else "✗"}')

                    cors = url_config.get('Cors', {})
                    allow_origins = cors.get('AllowOrigins', [])
                    if '*' in allow_origins:
                        protections.append('CORS wildcard ✗')
                    elif allow_origins:
                        protections.append('CORS restricted ✓')

                    results.append(self._build_finding(
                        account_id, region, func['FunctionName'], 'Lambda URL', protections,
                        {'URL': url_config.get('FunctionUrl'), 'Runtime': func.get('Runtime')}
                    ))
                except lam.exceptions.ResourceNotFoundException:
                    continue
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking Lambda URLs: {e}")
        return results

    # --- CloudFront ---
    def _check_cloudfront(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        if region != 'us-east-1':
            return []
        results = []
        try:
            cf = session.client('cloudfront')
            waf = session.client('wafv2', region_name='us-east-1')
            account_id = self._get_account_id(session)

            dists = cf.list_distributions()
            if 'DistributionList' not in dists or 'Items' not in dists['DistributionList']:
                return results

            for dist in dists['DistributionList']['Items']:
                if not dist.get('Enabled', False):
                    continue

                protections = []
                protections.append('WAF ✓' if dist.get('WebACLId') else 'WAF ✗')

                viewer_protocol = dist.get('DefaultCacheBehavior', {}).get('ViewerProtocolPolicy', '')
                protections.append('HTTPS ✓' if viewer_protocol in ['https-only', 'redirect-to-https'] else 'HTTPS ✗')

                tls_version = dist.get('ViewerCertificate', {}).get('MinimumProtocolVersion', '')
                protections.append('TLS 1.2 ✓' if 'TLSv1.2' in tls_version else 'TLS 1.2 ✗')

                results.append(self._build_finding(
                    account_id, 'global', dist['Id'], 'CloudFront', protections,
                    {'DomainName': dist.get('DomainName'), 'Aliases': dist.get('Aliases', {}).get('Items', [])}
                ))
        except Exception as e:
            print(f"Error checking CloudFront exposure: {e}")
        return results

    # --- OpenSearch / Elasticsearch ---
    def _check_opensearch(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            os_client = session.client('opensearch', region_name=region)
            account_id = self._get_account_id(session)

            domain_names = os_client.list_domain_names().get('DomainNames', [])
            if not domain_names:
                return results

            domains = os_client.describe_domains(
                DomainNames=[d['DomainName'] for d in domain_names]
            )['DomainStatusList']

            for domain in domains:
                if domain.get('VPCOptions', {}).get('VPCId'):
                    continue

                protections = []
                protections.append('VPC ✗ (public endpoint)')

                access_policy = domain.get('AccessPolicies', '')
                if access_policy:
                    try:
                        policy = json.loads(access_policy)
                        has_wildcard = any(
                            stmt.get('Principal') in ['*', {'AWS': '*'}]
                            for stmt in policy.get('Statement', [])
                            if stmt.get('Effect') == 'Allow'
                        )
                        protections.append('Access Policy ✗ (wildcard)' if has_wildcard else 'Access Policy ✓')
                    except Exception:
                        pass

                encryption = domain.get('EncryptionAtRestOptions', {}).get('Enabled', False)
                protections.append('Encryption ✓' if encryption else 'Encryption ✗')

                https_enforced = domain.get('DomainEndpointOptions', {}).get('EnforceHTTPS', False)
                protections.append('HTTPS enforced ✓' if https_enforced else 'HTTPS enforced ✗')

                endpoint = domain.get('Endpoint') or domain.get('Endpoints', {}).get('vpc', '')
                results.append(self._build_finding(
                    account_id, region, domain['DomainName'], 'OpenSearch', protections,
                    {'Endpoint': endpoint, 'EngineVersion': domain.get('EngineVersion', '')}
                ))
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking OpenSearch exposure: {e}")
        return results

    # --- Redshift ---
    def _check_redshift(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            redshift = session.client('redshift', region_name=region)
            ec2 = session.client('ec2', region_name=region)
            account_id = self._get_account_id(session)

            for cluster in redshift.describe_clusters()['Clusters']:
                if not cluster.get('PubliclyAccessible', False):
                    continue

                protections = []
                for sg in cluster.get('VpcSecurityGroups', []):
                    try:
                        sg_detail = ec2.describe_security_groups(GroupIds=[sg['VpcSecurityGroupId']])
                        for rule in sg_detail['SecurityGroups'][0].get('IpPermissions', []):
                            if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                                protections.append('SG open to 0.0.0.0/0 ✗')
                            else:
                                protections.append('SG restricted ✓')
                    except Exception:
                        continue

                protections.append('Encrypted ✓' if cluster.get('Encrypted') else 'Encrypted ✗')

                results.append(self._build_finding(
                    account_id, region, cluster['ClusterIdentifier'], 'Redshift', protections,
                    {'NodeType': cluster.get('NodeType'), 'NumberOfNodes': cluster.get('NumberOfNodes')}
                ))
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Redshift exposure: {e}")
        return results

    # --- EKS ---
    def _check_eks(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            eks = session.client('eks', region_name=region)
            account_id = self._get_account_id(session)

            for cluster_name in eks.list_clusters().get('clusters', []):
                try:
                    cluster = eks.describe_cluster(name=cluster_name)['cluster']
                    vpc_config = cluster.get('resourcesVpcConfig', {})

                    if not vpc_config.get('endpointPublicAccess', True):
                        continue

                    protections = []
                    protections.append('Private endpoint ✓' if vpc_config.get('endpointPrivateAccess') else 'Private endpoint ✗')

                    public_cidrs = vpc_config.get('publicAccessCidrs', ['0.0.0.0/0'])
                    if public_cidrs == ['0.0.0.0/0']:
                        protections.append('Public CIDR 0.0.0.0/0 ✗')
                    else:
                        protections.append('Public CIDR restricted ✓')

                    logging_types = []
                    for log in cluster.get('logging', {}).get('clusterLogging', []):
                        if log.get('enabled'):
                            logging_types.extend(log.get('types', []))
                    protections.append('Audit logging ✓' if 'audit' in logging_types else 'Audit logging ✗')

                    results.append(self._build_finding(
                        account_id, region, cluster_name, 'EKS', protections,
                        {'Version': cluster.get('version'), 'Endpoint': cluster.get('endpoint')}
                    ))
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking EKS exposure: {e}")
        return results

    # --- ECR Public ---
    def _check_ecr_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        if region != 'us-east-1':
            return []
        results = []
        try:
            ecr_public = session.client('ecr-public', region_name='us-east-1')
            account_id = self._get_account_id(session)

            for repo in ecr_public.describe_repositories().get('repositories', []):
                results.append(self._build_finding(
                    account_id, 'global', repo['repositoryName'], 'ECR Public', [],
                    {'RepositoryUri': repo.get('repositoryUri', '')}
                ))
        except Exception:
            pass
        return results

    # --- SNS Public ---
    def _check_sns_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            sns = session.client('sns', region_name=region)
            account_id = self._get_account_id(session)

            for topic in sns.list_topics().get('Topics', []):
                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
                    policy = json.loads(attrs['Attributes'].get('Policy', '{}'))

                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ['*', {'AWS': '*'}]:
                            if not stmt.get('Condition', {}):
                                topic_name = topic['TopicArn'].split(':')[-1]
                                results.append(self._build_finding(
                                    account_id, region, topic_name, 'SNS Topic', [],
                                    {'TopicArn': topic['TopicArn']}
                                ))
                            break
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SNS exposure: {e}")
        return results

    # --- SQS Public ---
    def _check_sqs_public(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        results = []
        try:
            sqs = session.client('sqs', region_name=region)
            account_id = self._get_account_id(session)

            queues = sqs.list_queues().get('QueueUrls', [])
            for queue_url in queues:
                try:
                    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
                    policy = json.loads(attrs.get('Attributes', {}).get('Policy', '{}'))

                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ['*', {'AWS': '*'}]:
                            if not stmt.get('Condition', {}):
                                queue_name = queue_url.split('/')[-1]
                                results.append(self._build_finding(
                                    account_id, region, queue_name, 'SQS Queue', [],
                                    {'QueueUrl': queue_url}
                                ))
                            break
                except Exception:
                    continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking SQS exposure: {e}")
        return results
