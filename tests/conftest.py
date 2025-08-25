"""
Pytest configuration and shared fixtures
"""

import pytest
import sys
import os
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))


@pytest.fixture(scope="session")
def test_config():
    """Test configuration for InfoBlox audit"""
    return {
        'infoblox': {
            'host': 'test.infoblox.com',
            'username': 'testuser',
            'password': 'testpass',
            'port': 443,
            'version': '2.12',
            'ssl_verify': False,
            'timeout': 30
        },
        'dns_audit': {
            'enabled': True,
            'check_zones': True,
            'check_records': True,
            'check_security': True,
            'max_zones': 1000
        },
        'dhcp_audit': {
            'enabled': True,
            'check_scopes': True,
            'check_reservations': True,
            'check_policies': True,
            'max_scopes': 500,
            'utilization_threshold': 85
        },
        'security_audit': {
            'enabled': True,
            'auth_checks': {'enabled': True},
            'network_checks': {'enabled': True},
            'system_checks': {'enabled': True}
        },
        'compliance_audit': {
            'enabled': True,
            'frameworks': [
                {'name': 'SOX', 'enabled': True},
                {'name': 'PCI-DSS', 'enabled': True},
                {'name': 'SOC2', 'enabled': True}
            ]
        },
        'reporting': {
            'include_recommendations': True,
            'include_remediation': True,
            'severity_levels': ['critical', 'high', 'medium', 'low', 'info']
        }
    }


@pytest.fixture
def sample_grid_info():
    """Sample grid information"""
    return {
        'nios_version': '8.6.0',
        'grid_name': 'test-grid',
        'dns_recursion_enabled': True,
        'dns_recursion_acl': ['192.168.1.0/24'],
        'dns_forwarders': [
            {'address': '8.8.8.8', 'use_tls': False},
            {'address': '1.1.1.1', 'use_tls': True}
        ],
        'dns_port_randomization': True,
        'snmp_enabled': True,
        'snmp_version': 'v2c',
        'snmp_community': 'public',
        'security_logging_enabled': False,
        'log_retention_days': 30,
        'backup_enabled': True,
        'backup_encrypted': False,
        'ntp_enabled': True,
        'encryption_enabled': False,
        'security_monitoring_enabled': False,
        'audit_logging_enabled': False,
        'change_management_enabled': False,
        'logical_access_controls': False,
        'availability_controls': False,
        'confidentiality_controls': False,
        'audit_controls_enabled': False,
        'transmission_security_enabled': False,
        'data_retention_policy': False,
        'access_logging_enabled': False,
        'change_management_documented': False,
        'backup_recovery_tested': False
    }


@pytest.fixture
def sample_admin_users():
    """Sample admin users"""
    return [
        {
            'name': 'admin',
            'enabled': True,
            'admin_groups': ['super-admin', 'dns-admin'],
            'last_login_time': '2023-01-01T10:00:00Z',
            'creation_time': '2022-01-01T10:00:00Z'
        },
        {
            'name': 'testuser',
            'enabled': True,
            'admin_groups': ['dns-admin'],
            'last_login_time': '2023-01-15T14:30:00Z',
            'creation_time': '2023-01-01T09:00:00Z'
        },
        {
            'name': 'olduser',
            'enabled': False,
            'admin_groups': ['read-only'],
            'last_login_time': '2022-06-01T12:00:00Z',
            'creation_time': '2022-01-01T10:00:00Z'
        }
    ]


@pytest.fixture
def sample_dns_zones():
    """Sample DNS zones"""
    return [
        {
            'fqdn': 'example.com',
            'dnssec_enabled': False,
            'allow_transfer': [],
            'ns_group': ['ns1.example.com', 'ns2.example.com'],
            'zone_format': 'FORWARD'
        },
        {
            'fqdn': 'secure.com',
            'dnssec_enabled': True,
            'dnssec_key_rollover': {'enabled': True},
            'allow_transfer': ['192.168.1.10', '192.168.1.11'],
            'ns_group': ['ns1.secure.com', 'ns2.secure.com'],
            'zone_format': 'FORWARD'
        },
        {
            'fqdn': 'dynamic.com',
            'dnssec_enabled': False,
            'allow_transfer': ['any'],
            'ns_group': ['ns1.dynamic.com'],
            'zone_format': 'DYNAMIC',
            'aging_enabled': False
        }
    ]


@pytest.fixture
def sample_dns_records():
    """Sample DNS records"""
    return [
        {
            'name': 'www.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.100'
        },
        {
            'name': 'mail.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.101'
        },
        {
            'name': '*.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.200'
        },
        {
            'name': 'suspicious123456789.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.300'
        },
        {
            'name': 'test.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.100'
        },
        {
            'name': 'test.example.com',
            'type': 'A',
            'ipv4addr': '192.168.1.150'
        }
    ]


@pytest.fixture
def sample_dhcp_networks():
    """Sample DHCP networks"""
    return [
        {
            'network': '192.168.1.0/24',
            'enable_dhcp': True,
            'gateway': '192.168.1.1',
            'lease_time': 86400,
            'usage': [{'option': 'TOTAL', 'value': '200'}],
            'options': [
                {'name': 'routers', 'value': '192.168.1.1'},
                {'name': 'domain-name-servers', 'value': '192.168.1.10,8.8.8.8'},
                {'name': 'domain-name', 'value': 'example.com'}
            ]
        },
        {
            'network': '10.0.0.0/24',
            'enable_dhcp': False,
            'gateway': '',
            'lease_time': 3600,
            'usage': [{'option': 'TOTAL', 'value': '50'}],
            'options': []
        },
        {
            'network': '172.16.1.0/24',
            'enable_dhcp': True,
            'gateway': '172.16.1.1',
            'lease_time': 604800,  # 1 week
            'usage': [{'option': 'TOTAL', 'value': '240'}],
            'options': [
                {'name': 'routers', 'value': '172.16.1.1'},
                {'name': 'domain-name-servers', 'value': '1.1.1.1,8.8.4.4'}
            ]
        }
    ]


@pytest.fixture
def sample_dhcp_leases():
    """Sample DHCP leases"""
    return [
        {
            'address': '192.168.1.100',
            'hardware': '00:11:22:33:44:55',
            'binding_state': 'ACTIVE',
            'client_hostname': 'workstation1'
        },
        {
            'address': '192.168.1.101',
            'hardware': '00:11:22:33:44:56',
            'binding_state': 'STATIC',
            'client_hostname': 'server1',
            'comment': 'Production server'
        },
        {
            'address': '192.168.1.102',
            'hardware': '00:11:22:33:44:57',
            'binding_state': 'STATIC',
            'client_hostname': 'server2',
            'comment': ''
        },
        {
            'address': '192.168.1.103',
            'hardware': '00:11:22:33:44:58',
            'binding_state': 'ACTIVE',
            'client_hostname': 'very-long-suspicious-hostname-that-might-be-malicious-12345'
        }
    ]


@pytest.fixture
def sample_audit_results():
    """Sample audit results for testing report generation"""
    return {
        'DNSAudit': {
            'audit_type': 'DNS',
            'start_time': '2023-01-01T10:00:00',
            'end_time': '2023-01-01T10:05:00',
            'duration_seconds': 300,
            'zones_audited': 3,
            'findings': [
                {
                    'rule_id': 'DNS-001',
                    'severity': 'high',
                    'title': 'DNSSEC not enabled for zone: example.com',
                    'description': 'Enable DNSSEC to provide authentication and integrity',
                    'timestamp': '2023-01-01T10:01:00',
                    'details': {'zone': 'example.com'}
                },
                {
                    'rule_id': 'DNS-002',
                    'severity': 'critical',
                    'title': 'Zone transfers not restricted for zone: dynamic.com',
                    'description': 'Restrict zone transfers to authorized servers only',
                    'timestamp': '2023-01-01T10:02:00',
                    'details': {'zone': 'dynamic.com'}
                }
            ],
            'summary': {
                'total_findings': 2,
                'severity_breakdown': {'critical': 1, 'high': 1},
                'risk_level': 'Critical'
            }
        },
        'DHCPAudit': {
            'audit_type': 'DHCP',
            'start_time': '2023-01-01T10:05:00',
            'end_time': '2023-01-01T10:08:00',
            'duration_seconds': 180,
            'networks_audited': 3,
            'findings': [
                {
                    'rule_id': 'DHCP-001',
                    'severity': 'medium',
                    'title': 'High DHCP scope utilization: 85.5%',
                    'description': 'DHCP scope 172.16.1.0/24 is 85.5% utilized',
                    'timestamp': '2023-01-01T10:06:00',
                    'details': {'network': '172.16.1.0/24', 'utilization': 85.5}
                }
            ],
            'summary': {
                'total_findings': 1,
                'severity_breakdown': {'medium': 1},
                'risk_level': 'Medium'
            }
        }
    }
