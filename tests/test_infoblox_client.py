"""
Unit tests for InfoBlox API Client
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from api.infoblox_client import InfoBloxClient


class TestInfoBloxClient:
    """Test cases for InfoBloxClient"""
    
    @pytest.fixture
    def client_config(self):
        """Test configuration for InfoBlox client"""
        return {
            'host': 'test.infoblox.com',
            'username': 'testuser',
            'password': 'testpass',
            'port': 443,
            'version': '2.12',
            'ssl_verify': False,
            'timeout': 30
        }
    
    @pytest.fixture
    def client(self, client_config):
        """Create test client instance"""
        return InfoBloxClient(client_config)
    
    def test_client_initialization(self, client, client_config):
        """Test client initialization"""
        assert client.host == client_config['host']
        assert client.username == client_config['username']
        assert client.password == client_config['password']
        assert client.port == client_config['port']
        assert client.version == client_config['version']
        assert client.ssl_verify == client_config['ssl_verify']
        assert client.timeout == client_config['timeout']
        assert client.base_url == f"https://{client_config['host']}:{client_config['port']}/wapi/v{client_config['version']}/"
    
    @patch('api.infoblox_client.requests.Session.get')
    def test_successful_get_request(self, mock_get, client):
        """Test successful GET request"""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = [{'test': 'data'}]
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = client.get('test_endpoint')
        
        assert result == [{'test': 'data'}]
        mock_get.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.get')
    def test_failed_get_request(self, mock_get, client):
        """Test failed GET request"""
        # Mock failed response
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = client.get('test_endpoint')
        
        assert result is None
        mock_get.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.post')
    def test_successful_post_request(self, mock_post, client):
        """Test successful POST request"""
        # Mock response
        mock_response = Mock()
        mock_response.text = '"test_reference"'
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        result = client.post('test_endpoint', {'test': 'data'})
        
        assert result == 'test_reference'
        mock_post.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.post')
    def test_failed_post_request(self, mock_post, client):
        """Test failed POST request"""
        # Mock failed response
        mock_post.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = client.post('test_endpoint', {'test': 'data'})
        
        assert result is None
        mock_post.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.put')
    def test_successful_put_request(self, mock_put, client):
        """Test successful PUT request"""
        # Mock response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_put.return_value = mock_response
        
        result = client.put('test_ref', {'test': 'data'})
        
        assert result is True
        mock_put.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.put')
    def test_failed_put_request(self, mock_put, client):
        """Test failed PUT request"""
        # Mock failed response
        mock_put.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = client.put('test_ref', {'test': 'data'})
        
        assert result is False
        mock_put.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.delete')
    def test_successful_delete_request(self, mock_delete, client):
        """Test successful DELETE request"""
        # Mock response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_delete.return_value = mock_response
        
        result = client.delete('test_ref')
        
        assert result is True
        mock_delete.assert_called_once()
    
    @patch('api.infoblox_client.requests.Session.delete')
    def test_failed_delete_request(self, mock_delete, client):
        """Test failed DELETE request"""
        # Mock failed response
        mock_delete.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = client.delete('test_ref')
        
        assert result is False
        mock_delete.assert_called_once()
    
    @patch.object(InfoBloxClient, 'get')
    def test_test_connection_success(self, mock_get, client):
        """Test successful connection test"""
        mock_get.return_value = [{'test': 'data'}]
        
        result = client.test_connection()
        
        assert result is True
        mock_get.assert_called_once_with('grid')
    
    @patch.object(InfoBloxClient, 'get')
    def test_test_connection_failure(self, mock_get, client):
        """Test failed connection test"""
        mock_get.return_value = None
        
        result = client.test_connection()
        
        assert result is False
        mock_get.assert_called_once_with('grid')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_grid_info(self, mock_get, client):
        """Test get grid info"""
        mock_get.return_value = [{'grid': 'info'}]
        
        result = client.get_grid_info()
        
        assert result == {'grid': 'info'}
        mock_get.assert_called_once_with('grid')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dns_zones(self, mock_get, client):
        """Test get DNS zones"""
        mock_get.return_value = [{'zone': 'test.com'}]
        
        result = client.get_dns_zones()
        
        assert result == [{'zone': 'test.com'}]
        mock_get.assert_called_once_with('zone_auth')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dns_records_with_zone(self, mock_get, client):
        """Test get DNS records with zone filter"""
        mock_get.return_value = [{'record': 'test'}]
        
        result = client.get_dns_records('test.com')
        
        assert result == [{'record': 'test'}]
        mock_get.assert_called_once_with('record:a', params={'zone': 'test.com'})
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dns_records_without_zone(self, mock_get, client):
        """Test get DNS records without zone filter"""
        mock_get.return_value = [{'record': 'test'}]
        
        result = client.get_dns_records()
        
        assert result == [{'record': 'test'}]
        mock_get.assert_called_once_with('record:a', params=None)
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dhcp_networks(self, mock_get, client):
        """Test get DHCP networks"""
        mock_get.return_value = [{'network': '192.168.1.0/24'}]
        
        result = client.get_dhcp_networks()
        
        assert result == [{'network': '192.168.1.0/24'}]
        mock_get.assert_called_once_with('network')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dhcp_ranges(self, mock_get, client):
        """Test get DHCP ranges"""
        mock_get.return_value = [{'range': 'test'}]
        
        result = client.get_dhcp_ranges()
        
        assert result == [{'range': 'test'}]
        mock_get.assert_called_once_with('range')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_dhcp_leases(self, mock_get, client):
        """Test get DHCP leases"""
        mock_get.return_value = [{'lease': 'test'}]
        
        result = client.get_dhcp_leases()
        
        assert result == [{'lease': 'test'}]
        mock_get.assert_called_once_with('lease')
    
    @patch.object(InfoBloxClient, 'get')
    def test_get_admin_users(self, mock_get, client):
        """Test get admin users"""
        mock_get.return_value = [{'user': 'admin'}]
        
        result = client.get_admin_users()
        
        assert result == [{'user': 'admin'}]
        mock_get.assert_called_once_with('adminuser')
    
    @patch.object(InfoBloxClient, 'get')
    def test_search_objects(self, mock_get, client):
        """Test search objects"""
        mock_get.return_value = [{'object': 'test'}]
        search_fields = {'name': 'test', 'type': 'A'}
        
        result = client.search_objects('record:a', search_fields)
        
        assert result == [{'object': 'test'}]
        mock_get.assert_called_once_with('record:a', params=search_fields)
