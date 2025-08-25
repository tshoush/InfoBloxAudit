"""
DHCP Audit Module
Performs comprehensive DHCP configuration and security audits
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import ipaddress

from api.infoblox_client import InfoBloxClient
from utils.helpers import load_audit_rules, validate_ip_address

logger = logging.getLogger(__name__)


class DHCPAudit:
    """DHCP configuration and security audit"""
    
    def __init__(self, client: InfoBloxClient, config: Dict[str, Any]):
        """
        Initialize DHCP audit
        
        Args:
            client: InfoBlox API client
            config: DHCP audit configuration
        """
        self.client = client
        self.config = config
        self.rules = load_audit_rules().get('dhcp_rules', {})
        self.findings = []
    
    def run(self) -> Dict[str, Any]:
        """
        Run complete DHCP audit
        
        Returns:
            Audit results dictionary
        """
        logger.info("Starting DHCP audit...")
        
        start_time = datetime.now()
        
        try:
            # Get DHCP data
            networks = self.client.get_dhcp_networks() or []
            ranges = self.client.get_dhcp_ranges() or []
            leases = self.client.get_dhcp_leases() or []
            
            # Perform audit checks
            if self.config.get('check_scopes', True):
                self._audit_scopes(networks, ranges)
            
            if self.config.get('check_reservations', True):
                self._audit_reservations(leases)
            
            if self.config.get('check_policies', True):
                self._audit_policies(networks)
            
            # Additional security checks
            self._audit_security(networks, ranges, leases)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'audit_type': 'DHCP',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'networks_audited': len(networks),
                'ranges_audited': len(ranges),
                'leases_audited': len(leases),
                'findings': self.findings,
                'summary': self._generate_summary()
            }
            
            logger.info(f"DHCP audit completed in {duration:.2f} seconds")
            return results
            
        except Exception as e:
            logger.error(f"DHCP audit failed: {str(e)}")
            raise
    
    def _audit_scopes(self, networks: List[Dict], ranges: List[Dict]) -> None:
        """Audit DHCP scopes and utilization"""
        logger.info(f"Auditing {len(networks)} DHCP networks and {len(ranges)} ranges...")
        
        for network in networks:
            network_addr = network.get('network', 'Unknown')
            
            # Check scope utilization
            self._check_scope_utilization(network, ranges)
            
            # Check scope configuration
            self._check_scope_configuration(network)
            
            # Check lease duration
            self._check_lease_duration(network)
            
            # Check scope options
            self._check_scope_options(network)
    
    def _audit_reservations(self, leases: List[Dict]) -> None:
        """Audit DHCP reservations"""
        logger.info("Auditing DHCP reservations...")
        
        static_leases = [lease for lease in leases if lease.get('binding_state') == 'STATIC']
        
        # Check for excessive static reservations
        if len(static_leases) > 100:  # Configurable threshold
            self._add_finding(
                'DHCP-RES-001',
                'medium',
                f'High number of static reservations: {len(static_leases)}',
                'Review static reservations for necessity and security',
                {'static_count': len(static_leases)}
            )
        
        # Check for conflicting reservations
        self._check_reservation_conflicts(static_leases)
        
        # Check reservation documentation
        self._check_reservation_documentation(static_leases)
    
    def _audit_policies(self, networks: List[Dict]) -> None:
        """Audit DHCP policies and options"""
        logger.info("Auditing DHCP policies...")
        
        for network in networks:
            # Check security-related options
            self._check_security_options(network)
            
            # Check DNS configuration
            self._check_dns_options(network)
            
            # Check vendor-specific options
            self._check_vendor_options(network)
    
    def _audit_security(self, networks: List[Dict], ranges: List[Dict], leases: List[Dict]) -> None:
        """Audit DHCP security settings"""
        logger.info("Auditing DHCP security settings...")
        
        # Check for rogue DHCP detection
        self._check_rogue_dhcp_protection()
        
        # Check lease time security
        self._check_lease_time_security(networks)
        
        # Check unauthorized clients
        self._check_unauthorized_clients(leases)
        
        # Check failover configuration
        self._check_failover_configuration(networks)
    
    def _check_scope_utilization(self, network: Dict, ranges: List[Dict]) -> None:
        """Check DHCP scope utilization"""
        network_addr = network.get('network', 'Unknown')
        
        # Calculate utilization
        total_addresses = 0
        used_addresses = 0
        
        try:
            net = ipaddress.ip_network(network_addr, strict=False)
            total_addresses = net.num_addresses - 2  # Exclude network and broadcast
            
            # Get usage statistics from network object
            usage = network.get('usage', [])
            for usage_item in usage:
                if usage_item.get('option') == 'TOTAL':
                    used_addresses = int(usage_item.get('value', 0))
                    break
            
            if total_addresses > 0:
                utilization = (used_addresses / total_addresses) * 100
                
                # Check against threshold
                threshold = self.config.get('utilization_threshold', 85)
                if utilization > threshold:
                    self._add_finding(
                        'DHCP-001',
                        'medium' if utilization < 95 else 'high',
                        f'High DHCP scope utilization: {utilization:.1f}%',
                        f'DHCP scope {network_addr} is {utilization:.1f}% utilized',
                        {
                            'network': network_addr,
                            'utilization': utilization,
                            'used': used_addresses,
                            'total': total_addresses
                        }
                    )
        
        except Exception as e:
            logger.warning(f"Failed to calculate utilization for {network_addr}: {str(e)}")
    
    def _check_scope_configuration(self, network: Dict) -> None:
        """Check DHCP scope configuration"""
        network_addr = network.get('network', 'Unknown')
        
        # Check if scope is enabled
        if not network.get('enable_dhcp', True):
            self._add_finding(
                'DHCP-002',
                'info',
                f'DHCP disabled for network: {network_addr}',
                'Verify if DHCP should be enabled for this network',
                {'network': network_addr}
            )
        
        # Check for proper gateway configuration
        gateway = network.get('gateway', '')
        if not gateway:
            self._add_finding(
                'DHCP-003',
                'medium',
                f'No gateway configured for network: {network_addr}',
                'Configure default gateway for DHCP clients',
                {'network': network_addr}
            )
    
    def _check_lease_duration(self, network: Dict) -> None:
        """Check DHCP lease duration settings"""
        network_addr = network.get('network', 'Unknown')
        
        lease_time = network.get('lease_time', 0)
        
        # Check for very short lease times
        if lease_time < 3600:  # Less than 1 hour
            self._add_finding(
                'DHCP-004',
                'medium',
                f'Very short lease time: {lease_time}s for network {network_addr}',
                'Short lease times can cause excessive DHCP traffic',
                {'network': network_addr, 'lease_time': lease_time}
            )
        
        # Check for very long lease times
        elif lease_time > 86400 * 7:  # More than 1 week
            self._add_finding(
                'DHCP-005',
                'low',
                f'Very long lease time: {lease_time}s for network {network_addr}',
                'Long lease times may delay IP address reclamation',
                {'network': network_addr, 'lease_time': lease_time}
            )
    
    def _check_scope_options(self, network: Dict) -> None:
        """Check DHCP scope options"""
        network_addr = network.get('network', 'Unknown')
        options = network.get('options', [])
        
        # Check for essential options
        essential_options = ['routers', 'domain-name-servers', 'domain-name']
        configured_options = [opt.get('name', '') for opt in options]
        
        for essential in essential_options:
            if essential not in configured_options:
                self._add_finding(
                    'DHCP-006',
                    'medium',
                    f'Missing essential DHCP option: {essential} for network {network_addr}',
                    f'Configure {essential} option for proper client functionality',
                    {'network': network_addr, 'missing_option': essential}
                )
    
    def _check_reservation_conflicts(self, static_leases: List[Dict]) -> None:
        """Check for conflicting DHCP reservations"""
        ip_map = {}
        mac_map = {}
        
        for lease in static_leases:
            ip_addr = lease.get('address', '')
            mac_addr = lease.get('hardware', '')
            
            # Check for IP conflicts
            if ip_addr in ip_map:
                self._add_finding(
                    'DHCP-RES-002',
                    'high',
                    f'Conflicting IP reservation: {ip_addr}',
                    'Multiple MAC addresses reserved for same IP',
                    {
                        'ip': ip_addr,
                        'macs': [ip_map[ip_addr], mac_addr]
                    }
                )
            ip_map[ip_addr] = mac_addr
            
            # Check for MAC conflicts
            if mac_addr in mac_map:
                self._add_finding(
                    'DHCP-RES-003',
                    'high',
                    f'Conflicting MAC reservation: {mac_addr}',
                    'Same MAC address reserved for multiple IPs',
                    {
                        'mac': mac_addr,
                        'ips': [mac_map[mac_addr], ip_addr]
                    }
                )
            mac_map[mac_addr] = ip_addr
    
    def _check_reservation_documentation(self, static_leases: List[Dict]) -> None:
        """Check if reservations are properly documented"""
        undocumented_count = 0
        
        for lease in static_leases:
            comment = lease.get('comment', '').strip()
            if not comment:
                undocumented_count += 1
        
        if undocumented_count > 0:
            self._add_finding(
                'DHCP-RES-004',
                'low',
                f'{undocumented_count} undocumented static reservations',
                'Add comments to static reservations for better management',
                {'undocumented_count': undocumented_count}
            )
    
    def _check_security_options(self, network: Dict) -> None:
        """Check security-related DHCP options"""
        # This would check for security-related DHCP options
        # Implementation depends on specific security requirements
        pass
    
    def _check_dns_options(self, network: Dict) -> None:
        """Check DNS-related DHCP options"""
        network_addr = network.get('network', 'Unknown')
        options = network.get('options', [])
        
        dns_servers = None
        for option in options:
            if option.get('name') == 'domain-name-servers':
                dns_servers = option.get('value', '')
                break
        
        if dns_servers:
            # Check if DNS servers are internal/trusted
            dns_list = dns_servers.split(',')
            for dns in dns_list:
                dns = dns.strip()
                if dns in ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']:
                    self._add_finding(
                        'DHCP-DNS-001',
                        'medium',
                        f'Public DNS server configured: {dns} for network {network_addr}',
                        'Consider using internal DNS servers for better security',
                        {'network': network_addr, 'dns_server': dns}
                    )
    
    def _check_vendor_options(self, network: Dict) -> None:
        """Check vendor-specific DHCP options"""
        # Implementation for vendor-specific option checks
        pass
    
    def _check_rogue_dhcp_protection(self) -> None:
        """Check for rogue DHCP protection"""
        # This would check if rogue DHCP protection is enabled
        # Implementation depends on InfoBlox API capabilities
        pass
    
    def _check_lease_time_security(self, networks: List[Dict]) -> None:
        """Check lease time from security perspective"""
        for network in networks:
            lease_time = network.get('lease_time', 0)
            network_addr = network.get('network', 'Unknown')
            
            # Very short lease times can be used for DoS attacks
            if lease_time < 300:  # Less than 5 minutes
                self._add_finding(
                    'DHCP-SEC-001',
                    'high',
                    f'Extremely short lease time: {lease_time}s for network {network_addr}',
                    'Very short lease times can be exploited for DoS attacks',
                    {'network': network_addr, 'lease_time': lease_time}
                )
    
    def _check_unauthorized_clients(self, leases: List[Dict]) -> None:
        """Check for potentially unauthorized clients"""
        # Look for unusual patterns in client identifiers
        suspicious_patterns = []
        
        for lease in leases:
            client_id = lease.get('client_hostname', '')
            if client_id and len(client_id) > 50:  # Unusually long hostname
                suspicious_patterns.append(client_id)
        
        if suspicious_patterns:
            self._add_finding(
                'DHCP-SEC-002',
                'medium',
                f'Suspicious client identifiers detected: {len(suspicious_patterns)}',
                'Review clients with unusual identifiers',
                {'suspicious_count': len(suspicious_patterns)}
            )
    
    def _check_failover_configuration(self, networks: List[Dict]) -> None:
        """Check DHCP failover configuration"""
        # Check if failover is configured for critical networks
        for network in networks:
            network_addr = network.get('network', 'Unknown')
            failover = network.get('failover_association', '')
            
            if not failover:
                self._add_finding(
                    'DHCP-FAIL-001',
                    'medium',
                    f'No failover configured for network: {network_addr}',
                    'Configure DHCP failover for high availability',
                    {'network': network_addr}
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
        logger.warning(f"DHCP Finding [{severity.upper()}]: {title}")
    
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
