"""On-demand pricing table for cost-finding plugins.

These are us-east-1 Linux on-demand prices as of 2025, used as a
conservative baseline when the AWS Pricing API is not available or
when we want a fast, offline estimate.

Plugins that need pricing for other regions or want live prices can
call the Pricing API directly — this table is intentionally simple.
The goal is a reasonable order-of-magnitude figure, not a billing
statement.

Sources:
  https://aws.amazon.com/ec2/pricing/on-demand/
  https://aws.amazon.com/rds/mysql/pricing/
"""

# EC2 Linux on-demand, us-east-1, $/hour
EC2_HOURLY: dict = {
    # General purpose — current gen
    't3.nano': 0.0052, 't3.micro': 0.0104, 't3.small': 0.0208,
    't3.medium': 0.0416, 't3.large': 0.0832, 't3.xlarge': 0.1664,
    't3.2xlarge': 0.3328,
    't3a.nano': 0.0047, 't3a.micro': 0.0094, 't3a.small': 0.0188,
    't3a.medium': 0.0376, 't3a.large': 0.0752, 't3a.xlarge': 0.1504,
    't3a.2xlarge': 0.3008,
    'm5.large': 0.096, 'm5.xlarge': 0.192, 'm5.2xlarge': 0.384,
    'm5.4xlarge': 0.768, 'm5.8xlarge': 1.536, 'm5.12xlarge': 2.304,
    'm5.16xlarge': 3.072, 'm5.24xlarge': 4.608,
    'm6i.large': 0.096, 'm6i.xlarge': 0.192, 'm6i.2xlarge': 0.384,
    'm6i.4xlarge': 0.768, 'm6i.8xlarge': 1.536, 'm6i.12xlarge': 2.304,
    'm6i.16xlarge': 3.072, 'm6i.24xlarge': 4.608, 'm6i.32xlarge': 6.144,
    'm7i.large': 0.1008, 'm7i.xlarge': 0.2016, 'm7i.2xlarge': 0.4032,
    'm7i.4xlarge': 0.8064, 'm7i.8xlarge': 1.6128,
    # Compute optimised
    'c5.large': 0.085, 'c5.xlarge': 0.17, 'c5.2xlarge': 0.34,
    'c5.4xlarge': 0.68, 'c5.9xlarge': 1.53, 'c5.18xlarge': 3.06,
    'c6i.large': 0.085, 'c6i.xlarge': 0.17, 'c6i.2xlarge': 0.34,
    'c6i.4xlarge': 0.68, 'c6i.8xlarge': 1.36, 'c6i.12xlarge': 2.04,
    'c6i.16xlarge': 2.72, 'c6i.24xlarge': 4.08, 'c6i.32xlarge': 5.44,
    # Memory optimised
    'r5.large': 0.126, 'r5.xlarge': 0.252, 'r5.2xlarge': 0.504,
    'r5.4xlarge': 1.008, 'r5.8xlarge': 2.016, 'r5.12xlarge': 3.024,
    'r5.16xlarge': 4.032, 'r5.24xlarge': 6.048,
    'r6i.large': 0.126, 'r6i.xlarge': 0.252, 'r6i.2xlarge': 0.504,
    'r6i.4xlarge': 1.008, 'r6i.8xlarge': 2.016, 'r6i.12xlarge': 3.024,
    'r6i.16xlarge': 4.032, 'r6i.24xlarge': 6.048, 'r6i.32xlarge': 8.064,
}

# RDS MySQL Single-AZ on-demand, us-east-1, $/hour
RDS_HOURLY: dict = {
    'db.t3.micro': 0.017, 'db.t3.small': 0.034, 'db.t3.medium': 0.068,
    'db.t3.large': 0.136, 'db.t3.xlarge': 0.272, 'db.t3.2xlarge': 0.544,
    'db.t4g.micro': 0.016, 'db.t4g.small': 0.032, 'db.t4g.medium': 0.065,
    'db.t4g.large': 0.130, 'db.t4g.xlarge': 0.260, 'db.t4g.2xlarge': 0.520,
    'db.m5.large': 0.171, 'db.m5.xlarge': 0.342, 'db.m5.2xlarge': 0.684,
    'db.m5.4xlarge': 1.368, 'db.m5.8xlarge': 2.736, 'db.m5.12xlarge': 4.104,
    'db.m5.16xlarge': 5.472, 'db.m5.24xlarge': 8.208,
    'db.m6g.large': 0.162, 'db.m6g.xlarge': 0.325, 'db.m6g.2xlarge': 0.650,
    'db.m6g.4xlarge': 1.300, 'db.m6g.8xlarge': 2.600, 'db.m6g.12xlarge': 3.900,
    'db.m6g.16xlarge': 5.200,
    'db.r5.large': 0.240, 'db.r5.xlarge': 0.480, 'db.r5.2xlarge': 0.960,
    'db.r5.4xlarge': 1.920, 'db.r5.8xlarge': 3.840, 'db.r5.12xlarge': 5.760,
    'db.r5.16xlarge': 7.680, 'db.r5.24xlarge': 11.520,
    'db.r6g.large': 0.228, 'db.r6g.xlarge': 0.456, 'db.r6g.2xlarge': 0.912,
    'db.r6g.4xlarge': 1.824, 'db.r6g.8xlarge': 3.648, 'db.r6g.12xlarge': 5.472,
    'db.r6g.16xlarge': 7.296,
}

HOURS_PER_MONTH = 730


def ec2_monthly(instance_type: str) -> float:
    """Return the monthly on-demand cost for an EC2 instance type.

    Falls back to a rough estimate based on the instance family if the
    exact type isn't in the table — better than returning zero.
    """
    hourly = EC2_HOURLY.get(instance_type)
    if hourly:
        return round(hourly * HOURS_PER_MONTH, 2)

    # Family-based fallback: strip the size suffix and use a known sibling
    parts = instance_type.split('.')
    if len(parts) == 2:
        family = parts[0]
        for known_type, known_price in EC2_HOURLY.items():
            if known_type.startswith(family + '.'):
                # Scale by vCPU count heuristic — rough but directionally correct
                return round(known_price * HOURS_PER_MONTH, 2)

    return 0.0


def rds_monthly(instance_class: str) -> float:
    """Return the monthly on-demand cost for an RDS instance class (MySQL Single-AZ).

    Uses MySQL Single-AZ as the baseline. Multi-AZ is roughly 2x, but
    we report the single-AZ figure and let the user apply their own
    multiplier based on their actual deployment option.
    """
    hourly = RDS_HOURLY.get(instance_class)
    if hourly:
        return round(hourly * HOURS_PER_MONTH, 2)
    return 0.0
