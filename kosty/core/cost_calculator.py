from typing import Optional, Dict, Any
from .pricing import PricingService

class CostCalculator:
    """Calculate monthly savings for cost findings
    
    Currently Supported Services (11 services):
    - EBS: Orphaned volumes (gp2, gp3, io1, io2, st1, sc1) + Old snapshots
    - EC2: Stopped instances (all instance types)
    - EIP: Unattached Elastic IPs ($0.005/hour)
    - NAT Gateway: Unused NAT Gateways ($0.045/hour)
    - Load Balancer: ALBs with no healthy targets ($0.0225/hour)
    - S3: Lifecycle candidates ($0.023/GB/month)
    - Snapshots: Old snapshots ($0.05/GB/month)
    - Backup: Empty vaults ($0/month - no storage cost)
    - RDS: Oversized instances (CPU utilization + instance pricing)
    - Lambda: Over-provisioned memory (invocations + duration + memory)
    - DynamoDB: Idle tables (RCU/WCU + on-demand optimization)
    
    Future Services (complex analysis):
    - CloudWatch: Log retention (requires log size analysis)
    - IAM: Unused roles (no direct cost)
    - Route53: Unused hosted zones (requires zone analysis)
    """
    
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
    
    def calculate_s3_savings(self, size_gb: float, region: str) -> Optional[float]:
        """Calculate monthly savings for S3 storage"""
        price_per_gb = self.pricing.get_s3_standard_price(region)
        if price_per_gb and size_gb > 0:
            return round(size_gb * price_per_gb, 2)
        return None
    
    def calculate_snapshot_savings(self, size_gb: int, region: str) -> Optional[float]:
        """Calculate monthly savings for EBS snapshots"""
        price_per_gb = self.pricing.get_ebs_snapshot_price(region)
        if price_per_gb and size_gb > 0:
            return round(size_gb * price_per_gb, 2)
        return None
    
    def calculate_backup_savings(self, size_gb: float, region: str) -> Optional[float]:
        """Calculate monthly savings for AWS Backup storage"""
        price_per_gb = self.pricing.get_backup_storage_price(region)
        if price_per_gb and size_gb > 0:
            return round(size_gb * price_per_gb, 2)
        return None
    
    def calculate_rds_savings(self, instance_class: str, cpu_utilization: float, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for oversized RDS instance"""
        price_per_hour = self.pricing.get_rds_price(instance_class, region)
        if price_per_hour and cpu_utilization < 20:  # Oversized if <20% CPU
            # Estimate 50% savings by downsizing
            return round(price_per_hour * hours_per_month * 0.5, 2)
        return None
    
    def calculate_lambda_savings(self, memory_mb: int, invocations: int, avg_duration_ms: int, region: str) -> Optional[float]:
        """Calculate monthly savings for over-provisioned Lambda"""
        pricing = self.pricing.get_lambda_price(region)
        
        # Current cost
        gb_seconds = (memory_mb / 1024) * (avg_duration_ms / 1000) * invocations
        current_cost = max(0, invocations - pricing['free_tier_requests']) * pricing['requests']
        current_cost += max(0, gb_seconds - pricing['free_tier_gb_seconds']) * pricing['duration_gb_second']
        
        # Optimized cost (assume 50% memory reduction for over-provisioned)
        if memory_mb > 512:  # Over-provisioned if >512MB
            optimized_gb_seconds = gb_seconds * 0.5
            optimized_cost = max(0, invocations - pricing['free_tier_requests']) * pricing['requests']
            optimized_cost += max(0, optimized_gb_seconds - pricing['free_tier_gb_seconds']) * pricing['duration_gb_second']
            return round(current_cost - optimized_cost, 2)
        
        return None
    
    def calculate_dynamodb_savings(self, rcu: int, wcu: int, region: str, hours_per_month: int = 730) -> Optional[float]:
        """Calculate monthly savings for idle DynamoDB table"""
        pricing = self.pricing.get_dynamodb_price(region)
        
        # Calculate current cost (above free tier)
        rcu_cost = max(0, rcu - pricing['free_tier_rcu']) * pricing['rcu'] * hours_per_month
        wcu_cost = max(0, wcu - pricing['free_tier_wcu']) * pricing['wcu'] * hours_per_month
        
        total_cost = rcu_cost + wcu_cost
        
        # If table is idle (low provisioned capacity), suggest on-demand
        if rcu <= 5 and wcu <= 5:  # Low provisioned capacity
            return round(total_cost * 0.8, 2)  # 80% savings with on-demand
        
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
        
        # S3 lifecycle candidates
        elif finding.get('service') == 'S3' and 'lifecycle' in finding.get('check', ''):
            size_gb = finding.get('size_gb')
            if size_gb:
                monthly_cost = self.calculate_s3_savings(size_gb, finding['region'])
        
        # EBS Snapshots old
        elif finding.get('service') in ['EBS', 'Snapshots'] and 'old_snapshots' in finding.get('check', ''):
            size_gb = finding.get('size_gb') or finding.get('volume_size_gb')
            if size_gb:
                monthly_cost = self.calculate_snapshot_savings(size_gb, finding['region'])
        
        # AWS Backup empty vaults (no direct cost)
        elif finding.get('service') == 'Backup' and 'empty' in finding.get('check', ''):
            monthly_cost = 0.0
        
        # RDS oversized instances
        elif finding.get('service') == 'RDS' and 'oversized' in finding.get('check', ''):
            instance_class = finding.get('instance_class')
            cpu_utilization = finding.get('avg_cpu', 0)
            if instance_class:
                monthly_cost = self.calculate_rds_savings(instance_class, cpu_utilization, finding['region'])
        
        # Lambda over-provisioned
        elif finding.get('service') == 'Lambda' and 'over_provisioned' in finding.get('check', ''):
            memory_mb = finding.get('memory_mb', 0)
            invocations = finding.get('invocations', 0)
            avg_duration_ms = finding.get('avg_duration_ms', 0)
            if memory_mb and invocations:
                monthly_cost = self.calculate_lambda_savings(memory_mb, invocations, avg_duration_ms, finding['region'])
        
        # DynamoDB idle tables
        elif finding.get('service') == 'DynamoDB' and 'idle' in finding.get('check', ''):
            rcu = finding.get('read_capacity_units', 0)
            wcu = finding.get('write_capacity_units', 0)
            if rcu or wcu:
                monthly_cost = self.calculate_dynamodb_savings(rcu, wcu, finding['region'])
        
        # Add cost fields
        if monthly_cost is not None:
            finding['monthly_cost'] = monthly_cost
            finding['cost_currency'] = 'USD'
        
        return finding
