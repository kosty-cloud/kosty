import boto3
from typing import List, Dict, Any
from datetime import datetime, timedelta


class ACMAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_expiring_certificates']

    def find_expiring_certificates(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find ACM certificates expiring within X days"""
        acm = session.client('acm', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = acm.get_paginator('list_certificates')
            cutoff = datetime.now() + timedelta(days=days)

            for page in paginator.paginate(CertificateStatuses=['ISSUED']):
                for cert in page['CertificateSummaryList']:
                    not_after = cert.get('NotAfter')
                    if not not_after:
                        continue

                    if not_after.replace(tzinfo=None) < cutoff:
                        days_left = (not_after.replace(tzinfo=None) - datetime.now()).days
                        severity = 'critical' if days_left < 7 else 'high' if days_left < 14 else 'medium'

                        results.append({
                            'AccountId': account_id, 'Region': region, 'Service': 'ACM',
                            'ResourceId': cert['DomainName'],
                            'ResourceName': cert['DomainName'],
                            'ARN': cert['CertificateArn'],
                            'Issue': f'Certificate expires in {days_left} days',
                            'type': 'security',
                            'Risk': 'Service outage when certificate expires',
                            'severity': severity, 'check': 'expiring_certificates',
                            'Details': {
                                'DomainName': cert['DomainName'],
                                'NotAfter': not_after.isoformat(),
                                'DaysLeft': days_left,
                                'Type': cert.get('Type', ''),
                                'RenewalEligibility': cert.get('RenewalEligibility', '')
                            }
                        })
        except Exception as e:
            print(f"Error checking ACM certificates: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return []

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.security_audit(session, region, config_manager=config_manager, **kwargs)

    def check_expiring_certificates(self, session, region, **kwargs):
        return self.find_expiring_certificates(session, region, **kwargs)
