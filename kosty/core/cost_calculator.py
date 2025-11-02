from typing import Optional, Dict, Any
from .pricing import PricingService

class CostCalculator:
    """Calculate monthly savings for cost findings"""
    
    def __init__(self):
        self.pricing = PricingService()
    
    def calculate_ebs_savings(self, volume_size_gb: int, volume_type: str, region: str) -> Optional[float]:
        """Calculate monthly savings for orphaned EBS volume"""
        price_per_gb = self.pricing.get_ebs_price(volume_type, region)
        if price_per_gb:
            return round(volume_size_gb * price_per_gb, 2)
        return None
    
    def calculate_ec2_savings(self, instance_type: str, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for stopped EC2 instance"""
        price_per_hour = self.pricing.get_ec2_price(instance_type, region)
        if price_per_hour:
            return round(price_per_hour * hours_per_month, 2)
        return None
    
    def calculate_eip_savings(self, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for unattached EIP"""
        price_per_hour = self.pricing.get_eip_price(region)
        if price_per_hour:
            return round(price_per_hour * hours_per_month, 2)
        return None
    
    def calculate_nat_gateway_savings(self, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for unused NAT Gateway"""
        price_per_hour = self.pricing.get_nat_gateway_price(region)
        if price_per_hour:
            return round(price_per_hour * hours_per_month, 2)
        return None
    
    def calculate_alb_savings(self, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for ALB with no targets"""
        price_per_hour = self.pricing.get_alb_price(region)
        if price_per_hour:
            return round(price_per_hour * hours_per_month, 2)
        return None
    
    def add_cost_to_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add cost information to a finding based on its type"""
        if finding.get('type') != 'cost':
            return finding
        
        monthly_cost = None
        
        # EBS orphaned volumes
        if finding.get('service') == 'EBS' and finding.get('check') == 'orphan_volumes':
            size = finding.get('size_gb')
            volume_type = finding.get('volume_type', 'gp2')
            if size:
                monthly_cost = self.calculate_ebs_savings(size, volume_type, finding['region'])
        
        # EIP unattached
        elif finding.get('service') == 'EIP' and 'unattached' in finding.get('check', ''):
            monthly_cost = self.calculate_eip_savings(finding['region'])
        
        # EC2 stopped instances
        elif finding.get('service') == 'EC2' and 'stopped' in finding.get('check', ''):
            instance_type = finding.get('instance_type')
            if instance_type:
                monthly_cost = self.calculate_ec2_savings(instance_type, finding['region'])
        
        # NAT Gateway unused
        elif finding.get('service') == 'NAT' and 'unused' in finding.get('check', ''):
            monthly_cost = self.calculate_nat_gateway_savings(finding['region'])
        
        # Load Balancer no targets
        elif finding.get('service') == 'LoadBalancer' and 'no_healthy_targets' in finding.get('check', ''):
            monthly_cost = self.calculate_alb_savings(finding['region'])
        
        # Add cost fields
        if monthly_cost is not None:
            finding['monthly_cost'] = monthly_cost
            finding['cost_currency'] = 'USD'
        
        return finding
