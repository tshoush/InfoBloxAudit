"""
Utility functions and helpers for InfoBlox Audit Tool
"""

import logging
import yaml
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import json


def setup_logging(verbose: bool = False) -> None:
    """
    Setup logging configuration
    
    Args:
        verbose: Enable verbose logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_dir / "audit.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Load environment variables for sensitive data
        if 'infoblox' in config:
            if not config['infoblox'].get('password'):
                config['infoblox']['password'] = os.getenv('INFOBLOX_PASSWORD', '')
        
        return config
        
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Invalid YAML in config file: {str(e)}")


def load_audit_rules(rules_path: str = "config/audit_rules.yaml") -> Dict[str, Any]:
    """
    Load audit rules from YAML file
    
    Args:
        rules_path: Path to audit rules file
        
    Returns:
        Audit rules dictionary
    """
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to load audit rules: {str(e)}")
        return {}


def calculate_risk_score(findings: List[Dict[str, Any]], rules: Dict[str, Any]) -> int:
    """
    Calculate overall risk score based on findings
    
    Args:
        findings: List of audit findings
        rules: Audit rules configuration
        
    Returns:
        Risk score (0-100)
    """
    if not findings:
        return 0
    
    risk_weights = rules.get('risk_scoring', {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 1
    })
    
    total_score = 0
    max_possible_score = 0
    
    for finding in findings:
        severity = finding.get('severity', 'low')
        weight = risk_weights.get(severity, 1)
        total_score += weight
        max_possible_score += risk_weights.get('critical', 10)
    
    if max_possible_score == 0:
        return 0
    
    # Normalize to 0-100 scale
    risk_score = min(100, (total_score / max_possible_score) * 100)
    return int(risk_score)


def format_timestamp(timestamp: datetime = None) -> str:
    """
    Format timestamp for reports
    
    Args:
        timestamp: Datetime object, defaults to current time
        
    Returns:
        Formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now()
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file operations
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Deep merge two dictionaries
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP address
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain_name(domain: str) -> bool:
    """
    Validate domain name format
    
    Args:
        domain: Domain name string
        
    Returns:
        True if valid domain name
    """
    import re
    
    # Basic domain name validation regex
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    
    if not domain or len(domain) > 253:
        return False
    
    return bool(re.match(pattern, domain))


def export_to_json(data: Dict[str, Any], filepath: str) -> bool:
    """
    Export data to JSON file
    
    Args:
        data: Data to export
        filepath: Output file path
        
    Returns:
        True if successful
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        logging.error(f"Failed to export JSON: {str(e)}")
        return False


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """
    Split list into chunks of specified size
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
