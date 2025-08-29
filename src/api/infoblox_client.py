"""
InfoBlox API Client
Handles communication with InfoBlox WAPI (Web API)
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import urllib3

from src.config_models import InfoBloxConfig

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class InfoBloxClient:
    """Client for InfoBlox WAPI communication"""
    
    def __init__(self, config: InfoBloxConfig):
        """
        Initialize InfoBlox client
        
        Args:
            config: Configuration object containing connection details
        """
        self.host = config.host
        self.username = config.username
        self.password = config.password.get_secret_value()
        self.port = config.port
        self.version = config.version
        self.ssl_verify = config.ssl_verify
        self.timeout = config.timeout
        
        self.base_url = f"https://{self.host}:{self.port}/wapi/v{self.version}/"
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.ssl_verify
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def test_connection(self) -> bool:
        """
        Test connection to InfoBlox appliance
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            response = self.get('grid')
            return response is not None
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            return False
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[List[Dict]]:
        """
        Perform GET request to InfoBlox WAPI
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            
        Returns:
            Response data or None if error
        """
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {endpoint}: {e.response.status_code} {e.response.reason}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {endpoint}: {str(e)}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {endpoint}: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request failed for {endpoint}: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {endpoint}: {str(e)}")
            return None
    
    def post(self, endpoint: str, data: Dict) -> Optional[str]:
        """
        Perform POST request to InfoBlox WAPI
        
        Args:
            endpoint: API endpoint
            data: Request data
            
        Returns:
            Response reference or None if error
        """
        try:
            url = urljoin(self.base_url, endpoint)
            response = self.session.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            
            return response.text.strip('"')
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {endpoint}: {e.response.status_code} {e.response.reason}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {endpoint}: {str(e)}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {endpoint}: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed for {endpoint}: {str(e)}")
            return None
    
    def put(self, ref: str, data: Dict) -> bool:
        """
        Perform PUT request to InfoBlox WAPI
        
        Args:
            ref: Object reference
            data: Update data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            url = urljoin(self.base_url, ref)
            response = self.session.put(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {ref}: {e.response.status_code} {e.response.reason}")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {ref}: {str(e)}")
            return False
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {ref}: {str(e)}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"PUT request failed for {ref}: {str(e)}")
            return False
    
    def delete(self, ref: str) -> bool:
        """
        Perform DELETE request to InfoBlox WAPI
        
        Args:
            ref: Object reference
            
        Returns:
            True if successful, False otherwise
        """
        try:
            url = urljoin(self.base_url, ref)
            response = self.session.delete(url, timeout=self.timeout)
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error for {ref}: {e.response.status_code} {e.response.reason}")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {ref}: {str(e)}")
            return False
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout for {ref}: {str(e)}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"DELETE request failed for {ref}: {str(e)}")
            return False
    
    def get_grid_info(self) -> Optional[Dict]:
        """Get grid information"""
        grids = self.get('grid')
        return grids[0] if grids else None
    
    def get_dns_zones(self) -> Optional[List[Dict]]:
        """Get all DNS zones"""
        return self.get('zone_auth')
    
    def get_dns_records(self, zone: str = None) -> Optional[List[Dict]]:
        """Get DNS records, optionally filtered by zone"""
        params = {'zone': zone} if zone else None
        return self.get('record:a', params=params)
    
    def get_dhcp_networks(self) -> Optional[List[Dict]]:
        """Get DHCP networks"""
        return self.get('network')
    
    def get_dhcp_ranges(self) -> Optional[List[Dict]]:
        """Get DHCP ranges"""
        return self.get('range')
    
    def get_dhcp_leases(self) -> Optional[List[Dict]]:
        """Get DHCP leases"""
        return self.get('lease')
    
    def get_admin_users(self) -> Optional[List[Dict]]:
        """Get admin users"""
        return self.get('adminuser')
    
    def get_grid_services(self) -> Optional[List[Dict]]:
        """Get grid services status"""
        return self.get('member:dns')
    
    def search_objects(self, object_type: str, search_fields: Dict) -> Optional[List[Dict]]:
        """
        Search for objects with specific criteria
        
        Args:
            object_type: Type of object to search
            search_fields: Search criteria
            
        Returns:
            List of matching objects
        """
        params = {}
        for field, value in search_fields.items():
            params[field] = value
            
        return self.get(object_type, params=params)
