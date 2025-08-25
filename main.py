#!/usr/bin/env python3
"""
InfoBlox Audit Tool - Main Entry Point
"""

import click
import yaml
import sys
import os
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from api.infoblox_client import InfoBloxClient
from audit.dns_audit import DNSAudit
from audit.dhcp_audit import DHCPAudit
from audit.security_audit import SecurityAudit
from audit.compliance_audit import ComplianceAudit
from reports.report_generator import ReportGenerator
from utils.helpers import setup_logging, load_config


@click.command()
@click.option('--target', '-t', required=True, help='InfoBlox appliance IP address or hostname')
@click.option('--username', '-u', help='Username for InfoBlox authentication')
@click.option('--password', '-p', help='Password for InfoBlox authentication')
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
@click.option('--output', '-o', default='reports', help='Output directory for reports')
@click.option('--format', '-f', type=click.Choice(['html', 'pdf', 'json', 'xlsx']), 
              default='html', help='Report output format')
@click.option('--audit-type', '-a', type=click.Choice(['all', 'dns', 'dhcp', 'security', 'compliance']), 
              default='all', help='Type of audit to perform')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(target, username, password, config, output, format, audit_type, verbose):
    """
    InfoBlox Audit Tool - Comprehensive security and compliance auditing for InfoBlox systems
    """
    
    # Setup logging
    setup_logging(verbose)
    
    try:
        # Load configuration
        config_data = load_config(config)
        
        # Override config with command line parameters
        if username:
            config_data['infoblox']['username'] = username
        if password:
            config_data['infoblox']['password'] = password
        
        config_data['infoblox']['host'] = target
        
        # Initialize InfoBlox client
        client = InfoBloxClient(config_data['infoblox'])
        
        # Verify connection
        if not client.test_connection():
            click.echo("❌ Failed to connect to InfoBlox appliance", err=True)
            sys.exit(1)
        
        click.echo(f"✅ Connected to InfoBlox appliance: {target}")
        
        # Initialize audit modules
        audits = []
        
        if audit_type in ['all', 'dns']:
            audits.append(DNSAudit(client, config_data.get('dns_audit', {})))
        
        if audit_type in ['all', 'dhcp']:
            audits.append(DHCPAudit(client, config_data.get('dhcp_audit', {})))
        
        if audit_type in ['all', 'security']:
            audits.append(SecurityAudit(client, config_data.get('security_audit', {})))
        
        if audit_type in ['all', 'compliance']:
            audits.append(ComplianceAudit(client, config_data.get('compliance_audit', {})))
        
        # Run audits
        results = {}
        for audit in audits:
            click.echo(f"🔍 Running {audit.__class__.__name__}...")
            results[audit.__class__.__name__] = audit.run()
        
        # Generate report
        report_gen = ReportGenerator(config_data.get('reporting', {}))
        report_path = report_gen.generate_report(results, output, format)
        
        click.echo(f"📊 Audit complete! Report saved to: {report_path}")
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
