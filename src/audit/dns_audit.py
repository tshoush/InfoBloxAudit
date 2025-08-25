"""
DNS Audit Module
Performs comprehensive DNS configuration and security audits
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

from api.infoblox_client import InfoBloxClient
from utils.helpers import load_audit_rules, validate_domain_name

logger = logging.getLogger(__name__)


class DNSAudit:
    """DNS configuration and security audit"""
    
    def __init__(self, client: InfoBloxClient, config: Dict[str, Any]):
        """
        Initialize DNS audit
        
        Args:
            client: InfoBlox API client
            config: DNS audit configuration
        """
        self.client = client
        self.config = config
        self.rules = load_audit_rules().get('dns_rules', {})
        self.findings = []
    
    def run(self) -> Dict[str, Any]:
        """
        Run complete DNS audit
        
        Returns:
            Audit results dictionary
        """
        logger.info("Starting DNS audit...")
        
        start_time = datetime.now()
        
        try:
            # Get DNS data
            zones = self.client.get_dns_zones() or []
            
            # Perform audit checks
            if self.config.get('check_zones', True):
                self._audit_zones(zones)
            
            if self.config.get('check_records', True):
                self._audit_records(zones)
            
            if self.config.get('check_security', True):
                self._audit_security()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'audit_type': 'DNS',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'zones_audited': len(zones),
                'findings': self.findings,
                'summary': self._generate_summary()
            }
            
            logger.info(f"DNS audit completed in {duration:.2f} seconds")
            return results
            
        except Exception as e:
            logger.error(f"DNS audit failed: {str(e)}")
            raise
    
    def _audit_zones(self, zones: List[Dict]) -> None:
        """Audit DNS zones configuration"""
        logger.info(f"Auditing {len(zones)} DNS zones...")
        
        for zone in zones:
            zone_name = zone.get('fqdn', 'Unknown')
            
            # Check DNSSEC configuration
            self._check_dnssec(zone)
            
            # Check zone transfer settings
            self._check_zone_transfers(zone)
            
            # Check zone delegation
            self._check_zone_delegation(zone)
            
            # Check zone aging/scavenging
            self._check_zone_aging(zone)
    
    def _audit_records(self, zones: List[Dict]) -> None:
        """Audit DNS records"""
        logger.info("Auditing DNS records...")
        
        for zone in zones:
            zone_name = zone.get('fqdn')
            if not zone_name:
                continue
            
            # Get records for this zone
            records = self.client.get_dns_records(zone_name) or []
            
            # Check for suspicious records
            self._check_suspicious_records(records, zone_name)
            
            # Check wildcard records
            self._check_wildcard_records(records, zone_name)
            
            # Check record consistency
            self._check_record_consistency(records, zone_name)
    
    def _audit_security(self) -> None:
        """Audit DNS security settings"""
        logger.info("Auditing DNS security settings...")
        
        # Get grid DNS properties
        grid_info = self.client.get_grid_info()
        if not grid_info:
            self._add_finding(
                'SEC-DNS-001',
                'critical',
                'Failed to retrieve grid DNS configuration',
                'Unable to audit DNS security settings'
            )
            return
        
        # Check recursion settings
        self._check_recursion_settings(grid_info)
        
        # Check forwarders configuration
        self._check_forwarders_security(grid_info)
        
        # Check cache poisoning protection
        self._check_cache_protection(grid_info)
    
    def _check_dnssec(self, zone: Dict) -> None:
        """Check DNSSEC configuration for zone"""
        zone_name = zone.get('fqdn', 'Unknown')
        
        # Check if DNSSEC is enabled
        dnssec_enabled = zone.get('dnssec_enabled', False)
        
        if not dnssec_enabled:
            self._add_finding(
                'DNS-001',
                'high',
                f'DNSSEC not enabled for zone: {zone_name}',
                'Enable DNSSEC to provide authentication and integrity for DNS responses',
                {'zone': zone_name}
            )
        
        # Check DNSSEC key rollover
        if dnssec_enabled:
            key_rollover = zone.get('dnssec_key_rollover', {})
            if not key_rollover.get('enabled', False):
                self._add_finding(
                    'DNS-001-A',
                    'medium',
                    f'DNSSEC key rollover not configured for zone: {zone_name}',
                    'Configure automatic key rollover for DNSSEC maintenance',
                    {'zone': zone_name}
                )
    
    def _check_zone_transfers(self, zone: Dict) -> None:
        """Check zone transfer security"""
        zone_name = zone.get('fqdn', 'Unknown')
        
        # Check if zone transfers are restricted
        allow_transfer = zone.get('allow_transfer', [])
        
        if not allow_transfer:
            # Zone transfers allowed to anyone
            self._add_finding(
                'DNS-002',
                'critical',
                f'Zone transfers not restricted for zone: {zone_name}',
                'Restrict zone transfers to authorized secondary servers only',
                {'zone': zone_name}
            )
        elif 'any' in allow_transfer:
            self._add_finding(
                'DNS-002-A',
                'critical',
                f'Zone transfers allowed to any host for zone: {zone_name}',
                'Remove "any" from zone transfer ACL and specify authorized servers',
                {'zone': zone_name}
            )
    
    def _check_zone_delegation(self, zone: Dict) -> None:
        """Check zone delegation configuration"""
        zone_name = zone.get('fqdn', 'Unknown')
        
        # Check for proper NS records
        ns_records = zone.get('ns_group', [])
        
        if len(ns_records) < 2:
            self._add_finding(
                'DNS-003',
                'medium',
                f'Insufficient name servers for zone: {zone_name}',
                'Configure at least 2 name servers for redundancy',
                {'zone': zone_name, 'ns_count': len(ns_records)}
            )
    
    def _check_zone_aging(self, zone: Dict) -> None:
        """Check zone aging and scavenging settings"""
        zone_name = zone.get('fqdn', 'Unknown')
        
        # Check if aging is enabled for dynamic zones
        zone_type = zone.get('zone_format', '')
        if 'DYNAMIC' in zone_type.upper():
            aging_enabled = zone.get('aging_enabled', False)
            
            if not aging_enabled:
                self._add_finding(
                    'DNS-004',
                    'low',
                    f'DNS aging not enabled for dynamic zone: {zone_name}',
                    'Enable DNS aging to automatically clean up stale records',
                    {'zone': zone_name}
                )
    
    def _check_suspicious_records(self, records: List[Dict], zone_name: str) -> None:
        """Check for potentially suspicious DNS records"""
        suspicious_patterns = [
            r'.*\.onion$',  # Tor hidden services
            r'.*dga.*',     # Domain generation algorithm patterns
            r'.*[0-9]{8,}.*',  # Long numeric sequences
            r'.*[a-z]{20,}.*',  # Very long random strings
        ]
        
        for record in records:
            record_name = record.get('name', '')
            record_type = record.get('type', '')
            
            for pattern in suspicious_patterns:
                if re.match(pattern, record_name, re.IGNORECASE):
                    self._add_finding(
                        'DNS-005',
                        'medium',
                        f'Suspicious DNS record detected: {record_name}',
                        'Review this record for potential security implications',
                        {
                            'zone': zone_name,
                            'record': record_name,
                            'type': record_type,
                            'pattern': pattern
                        }
                    )
    
    def _check_wildcard_records(self, records: List[Dict], zone_name: str) -> None:
        """Check for wildcard DNS records"""
        for record in records:
            record_name = record.get('name', '')
            
            if record_name.startswith('*'):
                self._add_finding(
                    'DNS-006',
                    'medium',
                    f'Wildcard DNS record found: {record_name}',
                    'Review wildcard records for security implications',
                    {
                        'zone': zone_name,
                        'record': record_name,
                        'type': record.get('type', '')
                    }
                )
    
    def _check_record_consistency(self, records: List[Dict], zone_name: str) -> None:
        """Check DNS record consistency"""
        # Check for duplicate A records
        a_records = {}
        for record in records:
            if record.get('type') == 'A':
                name = record.get('name', '')
                ip = record.get('ipv4addr', '')
                
                if name in a_records and a_records[name] != ip:
                    self._add_finding(
                        'DNS-007',
                        'medium',
                        f'Conflicting A records for {name}',
                        'Review and resolve conflicting DNS records',
                        {
                            'zone': zone_name,
                            'record': name,
                            'ips': [a_records[name], ip]
                        }
                    )
                a_records[name] = ip
    
    def _check_recursion_settings(self, grid_info: Dict) -> None:
        """Check DNS recursion configuration"""
        # Check if recursion is properly configured
        recursion_enabled = grid_info.get('dns_recursion_enabled', True)

        if recursion_enabled:
            # Check if recursion ACL is configured
            recursion_acl = grid_info.get('dns_recursion_acl', [])
            if not recursion_acl or 'any' in recursion_acl:
                self._add_finding(
                    'DNS-SEC-001',
                    'high',
                    'DNS recursion not properly restricted',
                    'Configure recursion ACL to limit recursive queries to authorized clients',
                    {'recursion_acl': recursion_acl}
                )

    def _check_forwarders_security(self, grid_info: Dict) -> None:
        """Check DNS forwarders security"""
        forwarders = grid_info.get('dns_forwarders', [])

        for forwarder in forwarders:
            forwarder_ip = forwarder.get('address', '')

            # Check if forwarder uses secure transport
            if not forwarder.get('use_tls', False):
                self._add_finding(
                    'DNS-SEC-002',
                    'medium',
                    f'DNS forwarder not using secure transport: {forwarder_ip}',
                    'Configure DNS over TLS (DoT) for secure forwarding',
                    {'forwarder': forwarder_ip}
                )

    def _check_cache_protection(self, grid_info: Dict) -> None:
        """Check cache poisoning protection"""
        # Check if source port randomization is enabled
        port_randomization = grid_info.get('dns_port_randomization', True)

        if not port_randomization:
            self._add_finding(
                'DNS-SEC-003',
                'high',
                'DNS source port randomization disabled',
                'Enable source port randomization to protect against cache poisoning attacks'
            )
    
    def _add_finding(self, rule_id: str, severity: str, title: str, 
                    description: str, details: Dict = None) -> None:
        """Add audit finding"""
        finding = {
            'rule_id': rule_id,
            'severity': severity,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
        
        self.findings.append(finding)
        logger.warning(f"DNS Finding [{severity.upper()}]: {title}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate audit summary"""
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'risk_level': self._calculate_risk_level(severity_counts)
        }
    
    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity_counts.get('critical', 0) > 0:
            return 'Critical'
        elif severity_counts.get('high', 0) > 2:
            return 'High'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 5:
            return 'Medium'
        else:
            return 'Low'
