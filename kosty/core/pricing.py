import boto3
import json
from typing import Optional, Dict, Any

class PricingService:
    """AWS Pricing API wrapper with caching"""
    
    def __init__(self):
        # Pricing API only available in us-east-1
        self.client = boto3.client('pricing', region_name='us-east-1')
        self.cache = {}
    
    def get_ebs_price(self, volume_type: str, region: str) -> Optional[float]:
        """Get EBS price per GB-month"""
        cache_key = f'ebs_{volume_type}_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'volumeApiName', 'Value': volume_type},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Storage'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                self.cache[cache_key] = price
                return price
        except Exception as e:
            print(f"Warning: Could not fetch EBS price for {volume_type} in {region}: {e}")
        
        return None
    
    def get_ec2_price(self, instance_type: str, region: str) -> Optional[float]:
        """Get EC2 price per hour"""
        cache_key = f'ec2_{instance_type}_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                    {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                    {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                    {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                self.cache[cache_key] = price
                return price
        except Exception as e:
            print(f"Warning: Could not fetch EC2 price for {instance_type} in {region}: {e}")
        
        return None
    
    def get_eip_price(self, region: str) -> Optional[float]:
        """Get EIP price per hour (unattached)
        
        AWS Pricing API does not reliably return EIP prices, so we use the official
        fixed price from AWS documentation. EIP pricing is consistent across all regions.
        
        Official AWS Pricing:
        - Unattached EIP: $0.005/hour ($3.60/month)
        - Additional EIP: $0.005/hour ($3.60/month)
        
        Source: https://aws.amazon.com/ec2/pricing/on-demand/#Elastic_IP_Addresses
        Last verified: November 2025
        """
        return 0.005  # $0.005 per hour for unattached EIP (all regions)
    
    def get_s3_standard_price(self, region: str) -> Optional[float]:
        """Get S3 Standard storage price per GB-month
        
        AWS S3 Standard pricing (first 50 TB tier):
        - us-east-1: $0.023/GB/month
        - Most regions: $0.023-0.025/GB/month
        
        Source: https://aws.amazon.com/s3/pricing/
        Last verified: November 2025
        """
        # Regional pricing variations are minimal for S3 Standard
        regional_prices = {
            'us-east-1': 0.023,
            'us-east-2': 0.023,
            'us-west-1': 0.025,
            'us-west-2': 0.023,
            'eu-west-1': 0.023,
            'eu-central-1': 0.024,
            'ap-southeast-1': 0.025,
            'ap-northeast-1': 0.025
        }
        return regional_prices.get(region, 0.023)  # Default to us-east-1 price
    
    def get_ebs_snapshot_price(self, region: str) -> Optional[float]:
        """Get EBS Snapshot price per GB-month
        
        AWS EBS Snapshot pricing:
        - Standard snapshots: $0.05/GB/month (all regions)
        
        Source: https://aws.amazon.com/ebs/pricing/
        Last verified: November 2025
        """
        return 0.05  # $0.05 per GB-month for EBS snapshots (all regions)
    
    def get_backup_storage_price(self, region: str) -> Optional[float]:
        """Get AWS Backup storage price per GB-month
        
        AWS Backup pricing:
        - Warm storage: $0.05/GB/month
        - Cold storage: $0.01/GB/month
        
        Using warm storage price as default.
        
        Source: https://aws.amazon.com/backup/pricing/
        Last verified: November 2025
        """
        return 0.05  # $0.05 per GB-month for backup warm storage
    
    def get_nat_gateway_price(self, region: str) -> Optional[float]:
        """Get NAT Gateway price per hour"""
        cache_key = f'nat_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'NAT Gateway'},
                    {'Type': 'TERM_MATCH', 'Field': 'usagetype', 'Value': f'NatGateway-Hours'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                self.cache[cache_key] = price
                return price
        except Exception as e:
            print(f"Warning: Could not fetch NAT Gateway price for {region}: {e}")
        
        return None
    
    def get_alb_price(self, region: str) -> Optional[float]:
        """Get Application Load Balancer price per hour"""
        cache_key = f'alb_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AWSELB',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Load Balancer-Application'},
                    {'Type': 'TERM_MATCH', 'Field': 'usagetype', 'Value': f'LoadBalancerUsage'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                self.cache[cache_key] = price
                return price
        except Exception as e:
            print(f"Warning: Could not fetch ALB price for {region}: {e}")
        
        return None
    
    def _get_location_name(self, region: str) -> str:
        """Convert region code to location name"""
        region_map = {
            'us-east-1': 'US East (N. Virginia)',
            'us-east-2': 'US East (Ohio)',
            'us-west-1': 'US West (N. California)',
            'us-west-2': 'US West (Oregon)',
            'eu-west-1': 'EU (Ireland)',
            'eu-west-2': 'EU (London)',
            'eu-west-3': 'EU (Paris)',
            'eu-central-1': 'EU (Frankfurt)',
            'eu-north-1': 'EU (Stockholm)',
            'ap-south-1': 'Asia Pacific (Mumbai)',
            'ap-northeast-1': 'Asia Pacific (Tokyo)',
            'ap-northeast-2': 'Asia Pacific (Seoul)',
            'ap-southeast-1': 'Asia Pacific (Singapore)',
            'ap-southeast-2': 'Asia Pacific (Sydney)',
            'ca-central-1': 'Canada (Central)',
            'sa-east-1': 'South America (Sao Paulo)'
        }
        return region_map.get(region, region)
    
    def get_rds_price(self, instance_class: str, region: str) -> Optional[float]:
        """Get RDS instance price per hour using AWS Pricing API"""
        cache_key = f'rds_{instance_class}_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AmazonRDS',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_class},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'databaseEngine', 'Value': 'MySQL'},
                    {'Type': 'TERM_MATCH', 'Field': 'deploymentOption', 'Value': 'Single-AZ'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                price = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                self.cache[cache_key] = price
                return price
        except Exception:
            pass
        
        # Fallback prices for common RDS instances (USD/hour)
        fallback_prices = {
            'db.t3.micro': 0.017, 'db.t3.small': 0.034, 'db.t3.medium': 0.068,
            'db.t3.large': 0.136, 'db.t3.xlarge': 0.272, 'db.t3.2xlarge': 0.544,
            'db.r5.large': 0.24, 'db.r5.xlarge': 0.48, 'db.r5.2xlarge': 0.96,
            'db.r5.4xlarge': 1.92, 'db.r5.8xlarge': 3.84
        }
        price = fallback_prices.get(instance_class, 0.10)
        self.cache[cache_key] = price
        return price
    
    def get_lambda_price(self, region: str) -> dict:
        """Get Lambda pricing components"""
        return {
            'requests': 0.0000002,  # $0.20 per 1M requests
            'duration_gb_second': 0.0000166667,  # $0.0000166667 per GB-second
            'free_tier_requests': 1000000,  # 1M free requests per month
            'free_tier_gb_seconds': 400000  # 400,000 GB-seconds per month
        }
    
    def get_dynamodb_price(self, region: str) -> dict:
        """Get DynamoDB pricing components"""
        return {
            'rcu': 0.00013,  # $0.00013 per RCU per hour
            'wcu': 0.00065,  # $0.00065 per WCU per hour
            'storage': 0.25,  # $0.25 per GB per month
            'free_tier_rcu': 25,  # 25 RCU free tier
            'free_tier_wcu': 25,  # 25 WCU free tier
            'free_tier_storage': 25  # 25 GB free tier
        }
