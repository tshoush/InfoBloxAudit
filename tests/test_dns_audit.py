"""
Unit tests for DNS Audit Module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from audit.dns_audit import DNSAudit
from api.infoblox_client import InfoBloxClient


class TestDNSAudit:
    """Test cases for DNSAudit"""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock InfoBlox client"""
        client = Mock(spec=InfoBloxClient)
        return client
    
    @pytest.fixture
    def audit_config(self):
        """Test configuration for DNS audit"""
        return {
            'enabled': True,
            'check_zones': True,
            'check_records': True,
            'check_security': True,
            'max_zones': 1000
        }
    
    @pytest.fixture
    def dns_audit(self, mock_client, audit_config):
        """Create DNS audit instance"""
        with patch('audit.dns_audit.load_audit_rules') as mock_load_rules:
            mock_load_rules.return_value = {'dns_rules': {}}
            return DNSAudit(mock_client, audit_config)
    
    @pytest.fixture
    def sample_zones(self):
        """Sample DNS zones data"""
        return [
            {
                'fqdn': 'example.com',
                'dnssec_enabled': False,
                'allow_transfer': [],
                'ns_group': ['ns1.example.com', 'ns2.example.com'],
                'zone_format': 'FORWARD'
            },
            {
                'fqdn': 'test.com',
                'dnssec_enabled': True,
                'allow_transfer': ['192.168.1.10'],
                'ns_group': ['ns1.test.com'],
                'zone_format': 'DYNAMIC'
            }
        ]
    
    @pytest.fixture
    def sample_records(self):
        """Sample DNS records data"""
        return [
            {
                'name': 'www.example.com',
                'type': 'A',
                'ipv4addr': '192.168.1.100'
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
            }
        ]
    
    def test_dns_audit_initialization(self, dns_audit, mock_client, audit_config):
        """Test DNS audit initialization"""
        assert dns_audit.client == mock_client
        assert dns_audit.config == audit_config
        assert dns_audit.findings == []
    
    def test_run_complete_audit(self, dns_audit, mock_client, sample_zones):
        """Test running complete DNS audit"""
        # Mock client methods
        mock_client.get_dns_zones.return_value = sample_zones
        mock_client.get_dns_records.return_value = []
        mock_client.get_grid_info.return_value = {'test': 'data'}
        
        result = dns_audit.run()
        
        # Verify result structure
        assert 'audit_type' in result
        assert 'start_time' in result
        assert 'end_time' in result
        assert 'duration_seconds' in result
        assert 'zones_audited' in result
        assert 'findings' in result
        assert 'summary' in result
        
        assert result['audit_type'] == 'DNS'
        assert result['zones_audited'] == len(sample_zones)
        assert isinstance(result['findings'], list)
    
    def test_audit_zones_dnssec_disabled(self, dns_audit, sample_zones):
        """Test DNSSEC disabled finding"""
        dns_audit._audit_zones(sample_zones)
        
        # Should find DNSSEC not enabled for example.com
        dnssec_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-001']
        assert len(dnssec_findings) == 1
        assert 'example.com' in dnssec_findings[0]['title']
        assert dnssec_findings[0]['severity'] == 'high'
    
    def test_audit_zones_zone_transfer_unrestricted(self, dns_audit, sample_zones):
        """Test unrestricted zone transfer finding"""
        dns_audit._audit_zones(sample_zones)
        
        # Should find unrestricted zone transfers for example.com
        transfer_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-002']
        assert len(transfer_findings) == 1
        assert 'example.com' in transfer_findings[0]['title']
        assert transfer_findings[0]['severity'] == 'critical'
    
    def test_audit_zones_insufficient_nameservers(self, dns_audit, sample_zones):
        """Test insufficient nameservers finding"""
        dns_audit._audit_zones(sample_zones)
        
        # Should find insufficient nameservers for test.com (only 1 NS)
        ns_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-003']
        assert len(ns_findings) == 1
        assert 'test.com' in ns_findings[0]['title']
        assert ns_findings[0]['severity'] == 'medium'
    
    def test_audit_records_wildcard_detection(self, dns_audit, sample_records):
        """Test wildcard record detection"""
        dns_audit._audit_records([{'fqdn': 'example.com'}])
        
        # Mock get_dns_records to return sample records
        with patch.object(dns_audit.client, 'get_dns_records', return_value=sample_records):
            dns_audit._audit_records([{'fqdn': 'example.com'}])
        
        # Should detect wildcard record
        wildcard_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-006']
        assert len(wildcard_findings) >= 1
    
    def test_audit_records_suspicious_patterns(self, dns_audit, sample_records):
        """Test suspicious record pattern detection"""
        with patch.object(dns_audit.client, 'get_dns_records', return_value=sample_records):
            dns_audit._audit_records([{'fqdn': 'example.com'}])
        
        # Should detect suspicious record with long numeric sequence
        suspicious_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-005']
        assert len(suspicious_findings) >= 1
    
    def test_check_dnssec_enabled(self, dns_audit):
        """Test DNSSEC check for enabled zone"""
        zone = {
            'fqdn': 'secure.com',
            'dnssec_enabled': True,
            'dnssec_key_rollover': {'enabled': False}
        }
        
        dns_audit._check_dnssec(zone)
        
        # Should find key rollover not configured
        rollover_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-001-A']
        assert len(rollover_findings) == 1
        assert rollover_findings[0]['severity'] == 'medium'
    
    def test_check_zone_transfers_any_allowed(self, dns_audit):
        """Test zone transfer check with 'any' allowed"""
        zone = {
            'fqdn': 'insecure.com',
            'allow_transfer': ['any', '192.168.1.10']
        }
        
        dns_audit._check_zone_transfers(zone)
        
        # Should find 'any' in transfer ACL
        any_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-002-A']
        assert len(any_findings) == 1
        assert any_findings[0]['severity'] == 'critical'
    
    def test_check_zone_aging_dynamic_zone(self, dns_audit):
        """Test zone aging check for dynamic zone"""
        zone = {
            'fqdn': 'dynamic.com',
            'zone_format': 'DYNAMIC',
            'aging_enabled': False
        }
        
        dns_audit._check_zone_aging(zone)
        
        # Should find aging not enabled for dynamic zone
        aging_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-004']
        assert len(aging_findings) == 1
        assert aging_findings[0]['severity'] == 'low'
    
    def test_check_record_consistency_conflicts(self, dns_audit):
        """Test record consistency check with conflicts"""
        records = [
            {'name': 'test.example.com', 'type': 'A', 'ipv4addr': '192.168.1.100'},
            {'name': 'test.example.com', 'type': 'A', 'ipv4addr': '192.168.1.200'}
        ]
        
        dns_audit._check_record_consistency(records, 'example.com')
        
        # Should find conflicting A records
        conflict_findings = [f for f in dns_audit.findings if f['rule_id'] == 'DNS-007']
        assert len(conflict_findings) == 1
        assert conflict_findings[0]['severity'] == 'medium'
    
    def test_add_finding(self, dns_audit):
        """Test adding audit finding"""
        initial_count = len(dns_audit.findings)
        
        dns_audit._add_finding(
            'TEST-001',
            'high',
            'Test finding',
            'Test description',
            {'test': 'details'}
        )
        
        assert len(dns_audit.findings) == initial_count + 1
        
        finding = dns_audit.findings[-1]
        assert finding['rule_id'] == 'TEST-001'
        assert finding['severity'] == 'high'
        assert finding['title'] == 'Test finding'
        assert finding['description'] == 'Test description'
        assert finding['details'] == {'test': 'details'}
        assert 'timestamp' in finding
    
    def test_generate_summary(self, dns_audit):
        """Test summary generation"""
        # Add some test findings
        dns_audit._add_finding('TEST-001', 'critical', 'Critical issue', 'Description')
        dns_audit._add_finding('TEST-002', 'high', 'High issue', 'Description')
        dns_audit._add_finding('TEST-003', 'medium', 'Medium issue', 'Description')
        
        summary = dns_audit._generate_summary()
        
        assert summary['total_findings'] == 3
        assert summary['severity_breakdown']['critical'] == 1
        assert summary['severity_breakdown']['high'] == 1
        assert summary['severity_breakdown']['medium'] == 1
        assert summary['risk_level'] == 'Critical'  # Due to critical finding
    
    def test_calculate_risk_level(self, dns_audit):
        """Test risk level calculation"""
        # Test critical risk
        assert dns_audit._calculate_risk_level({'critical': 1}) == 'Critical'
        
        # Test high risk
        assert dns_audit._calculate_risk_level({'high': 3}) == 'High'
        
        # Test medium risk
        assert dns_audit._calculate_risk_level({'high': 1, 'medium': 3}) == 'Medium'
        
        # Test low risk
        assert dns_audit._calculate_risk_level({'low': 2}) == 'Low'
    
    def test_audit_security_grid_info_failure(self, dns_audit, mock_client):
        """Test security audit when grid info retrieval fails"""
        mock_client.get_grid_info.return_value = None
        
        dns_audit._audit_security()
        
        # Should add finding about failed grid configuration retrieval
        grid_findings = [f for f in dns_audit.findings if f['rule_id'] == 'SEC-DNS-001']
        assert len(grid_findings) == 1
        assert grid_findings[0]['severity'] == 'critical'
    
    @patch('audit.dns_audit.datetime')
    def test_run_timing(self, mock_datetime, dns_audit, mock_client):
        """Test audit timing calculation"""
        # Mock datetime to control timing
        start_time = datetime(2023, 1, 1, 10, 0, 0)
        end_time = datetime(2023, 1, 1, 10, 0, 30)  # 30 seconds later
        
        mock_datetime.now.side_effect = [start_time, end_time]
        mock_datetime.return_value = mock_datetime
        
        # Mock client methods
        mock_client.get_dns_zones.return_value = []
        mock_client.get_grid_info.return_value = {'test': 'data'}
        
        result = dns_audit.run()
        
        assert result['duration_seconds'] == 30.0
