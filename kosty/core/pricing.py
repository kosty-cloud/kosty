import boto3
import json
from typing import Optional, Dict

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
        """Get EIP price per hour (unattached)"""
        cache_key = f'eip_{region}'
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            response = self.client.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': self._get_location_name(region)},
                    {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'IP Address'},
                    {'Type': 'TERM_MATCH', 'Field': 'group', 'Value': 'ElasticIP:IdleAddress'}
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
            print(f"Warning: Could not fetch EIP price for {region}: {e}")
        
        return None
    
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
