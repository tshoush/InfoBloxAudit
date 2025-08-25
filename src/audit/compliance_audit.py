"""
Compliance Audit Module
Performs compliance audits against various frameworks (SOX, PCI-DSS, HIPAA, SOC2)
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from api.infoblox_client import InfoBloxClient
from utils.helpers import load_audit_rules

logger = logging.getLogger(__name__)


class ComplianceAudit:
    """Compliance audit against various frameworks"""
    
    def __init__(self, client: InfoBloxClient, config: Dict[str, Any]):
        """
        Initialize compliance audit
        
        Args:
            client: InfoBlox API client
            config: Compliance audit configuration
        """
        self.client = client
        self.config = config
        self.rules = load_audit_rules().get('compliance_rules', {})
        self.findings = []
        self.frameworks = config.get('frameworks', [])
    
    def run(self) -> Dict[str, Any]:
        """
        Run complete compliance audit
        
        Returns:
            Audit results dictionary
        """
        logger.info("Starting compliance audit...")
        
        start_time = datetime.now()
        
        try:
            # Get system information
            grid_info = self.client.get_grid_info()
            admin_users = self.client.get_admin_users() or []
            
            # Run framework-specific audits
            framework_results = {}
            
            for framework in self.frameworks:
                if framework.get('enabled', False):
                    framework_name = framework.get('name', '').upper()
                    logger.info(f"Running {framework_name} compliance audit...")
                    
                    if framework_name == 'SOX':
                        framework_results['SOX'] = self._audit_sox_compliance(grid_info, admin_users)
                    elif framework_name == 'PCI-DSS':
                        framework_results['PCI-DSS'] = self._audit_pci_compliance(grid_info, admin_users)
                    elif framework_name == 'HIPAA':
                        framework_results['HIPAA'] = self._audit_hipaa_compliance(grid_info, admin_users)
                    elif framework_name == 'SOC2':
                        framework_results['SOC2'] = self._audit_soc2_compliance(grid_info, admin_users)
            
            # General compliance checks
            self._audit_general_compliance(grid_info, admin_users)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'audit_type': 'Compliance',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'frameworks_audited': list(framework_results.keys()),
                'framework_results': framework_results,
                'findings': self.findings,
                'summary': self._generate_summary()
            }
            
            logger.info(f"Compliance audit completed in {duration:.2f} seconds")
            return results
            
        except Exception as e:
            logger.error(f"Compliance audit failed: {str(e)}")
            raise
    
    def _audit_sox_compliance(self, grid_info: Dict, admin_users: List[Dict]) -> Dict[str, Any]:
        """Audit SOX (Sarbanes-Oxley) compliance requirements"""
        sox_findings = []
        
        # SOX requires strong access controls
        self._check_sox_access_controls(admin_users, sox_findings)
        
        # SOX requires change management
        self._check_sox_change_management(grid_info, sox_findings)
        
        # SOX requires audit trails
        self._check_sox_audit_trails(grid_info, sox_findings)
        
        # SOX requires segregation of duties
        self._check_sox_segregation_duties(admin_users, sox_findings)
        
        return {
            'framework': 'SOX',
            'findings': sox_findings,
            'compliance_score': self._calculate_compliance_score(sox_findings),
            'status': self._determine_compliance_status(sox_findings)
        }
    
    def _audit_pci_compliance(self, grid_info: Dict, admin_users: List[Dict]) -> Dict[str, Any]:
        """Audit PCI-DSS compliance requirements"""
        pci_findings = []
        
        # PCI requires network segmentation
        self._check_pci_network_segmentation(grid_info, pci_findings)
        
        # PCI requires encryption
        self._check_pci_encryption(grid_info, pci_findings)
        
        # PCI requires access controls
        self._check_pci_access_controls(admin_users, pci_findings)
        
        # PCI requires monitoring
        self._check_pci_monitoring(grid_info, pci_findings)
        
        # PCI requires vulnerability management
        self._check_pci_vulnerability_management(grid_info, pci_findings)
        
        return {
            'framework': 'PCI-DSS',
            'findings': pci_findings,
            'compliance_score': self._calculate_compliance_score(pci_findings),
            'status': self._determine_compliance_status(pci_findings)
        }
    
    def _audit_hipaa_compliance(self, grid_info: Dict, admin_users: List[Dict]) -> Dict[str, Any]:
        """Audit HIPAA compliance requirements"""
        hipaa_findings = []
        
        # HIPAA requires access controls
        self._check_hipaa_access_controls(admin_users, hipaa_findings)
        
        # HIPAA requires audit controls
        self._check_hipaa_audit_controls(grid_info, hipaa_findings)
        
        # HIPAA requires integrity controls
        self._check_hipaa_integrity_controls(grid_info, hipaa_findings)
        
        # HIPAA requires transmission security
        self._check_hipaa_transmission_security(grid_info, hipaa_findings)
        
        return {
            'framework': 'HIPAA',
            'findings': hipaa_findings,
            'compliance_score': self._calculate_compliance_score(hipaa_findings),
            'status': self._determine_compliance_status(hipaa_findings)
        }
    
    def _audit_soc2_compliance(self, grid_info: Dict, admin_users: List[Dict]) -> Dict[str, Any]:
        """Audit SOC2 compliance requirements"""
        soc2_findings = []
        
        # SOC2 Trust Service Criteria
        
        # Security
        self._check_soc2_security(grid_info, admin_users, soc2_findings)
        
        # Availability
        self._check_soc2_availability(grid_info, soc2_findings)
        
        # Processing Integrity
        self._check_soc2_processing_integrity(grid_info, soc2_findings)
        
        # Confidentiality
        self._check_soc2_confidentiality(grid_info, soc2_findings)
        
        # Privacy (if applicable)
        self._check_soc2_privacy(grid_info, soc2_findings)
        
        return {
            'framework': 'SOC2',
            'findings': soc2_findings,
            'compliance_score': self._calculate_compliance_score(soc2_findings),
            'status': self._determine_compliance_status(soc2_findings)
        }
    
    def _audit_general_compliance(self, grid_info: Dict, admin_users: List[Dict]) -> None:
        """Audit general compliance requirements"""
        
        # Data retention policies
        self._check_data_retention(grid_info)
        
        # Access logging
        self._check_access_logging(grid_info)
        
        # Change management
        self._check_change_management(grid_info)
        
        # Backup and recovery
        self._check_backup_recovery(grid_info)
    
    # SOX-specific checks
    def _check_sox_access_controls(self, admin_users: List[Dict], findings: List[Dict]) -> None:
        """Check SOX access control requirements"""
        # Check for proper user access management
        inactive_users = [user for user in admin_users if not user.get('enabled', True)]
        
        if len(inactive_users) > 0:
            finding = self._create_finding(
                'SOX-001',
                'medium',
                f'{len(inactive_users)} inactive admin accounts detected',
                'SOX requires timely removal of inactive user accounts',
                {'inactive_count': len(inactive_users)}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_sox_change_management(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOX change management requirements"""
        # Check if change management is documented
        change_mgmt = grid_info.get('change_management_enabled', False)
        
        if not change_mgmt:
            finding = self._create_finding(
                'SOX-002',
                'high',
                'Change management not properly configured',
                'SOX requires documented change management processes',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_sox_audit_trails(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOX audit trail requirements"""
        audit_logging = grid_info.get('audit_logging_enabled', False)
        
        if not audit_logging:
            finding = self._create_finding(
                'SOX-003',
                'high',
                'Audit logging not enabled',
                'SOX requires comprehensive audit trails for all system activities',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_sox_segregation_duties(self, admin_users: List[Dict], findings: List[Dict]) -> None:
        """Check SOX segregation of duties"""
        # Check if same user has conflicting roles
        for user in admin_users:
            roles = user.get('admin_groups', [])
            if len(roles) > 3:  # Configurable threshold
                finding = self._create_finding(
                    'SOX-004',
                    'medium',
                    f'User with excessive roles: {user.get("name", "")}',
                    'SOX requires segregation of duties to prevent conflicts of interest',
                    {'username': user.get('name', ''), 'role_count': len(roles)}
                )
                findings.append(finding)
                self.findings.append(finding)
    
    # PCI-DSS specific checks
    def _check_pci_network_segmentation(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check PCI network segmentation requirements"""
        # This would check network segmentation controls
        # Implementation depends on InfoBlox network configuration API
        pass
    
    def _check_pci_encryption(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check PCI encryption requirements"""
        encryption_enabled = grid_info.get('encryption_enabled', False)
        
        if not encryption_enabled:
            finding = self._create_finding(
                'PCI-001',
                'critical',
                'Encryption not enabled',
                'PCI-DSS requires encryption of cardholder data in transit and at rest',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_pci_access_controls(self, admin_users: List[Dict], findings: List[Dict]) -> None:
        """Check PCI access control requirements"""
        # Check for unique user IDs
        usernames = [user.get('name', '') for user in admin_users]
        if len(usernames) != len(set(usernames)):
            finding = self._create_finding(
                'PCI-002',
                'high',
                'Duplicate usernames detected',
                'PCI-DSS requires unique user IDs for each person',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_pci_monitoring(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check PCI monitoring requirements"""
        monitoring_enabled = grid_info.get('security_monitoring_enabled', False)
        
        if not monitoring_enabled:
            finding = self._create_finding(
                'PCI-003',
                'high',
                'Security monitoring not enabled',
                'PCI-DSS requires monitoring and testing of networks',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_pci_vulnerability_management(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check PCI vulnerability management requirements"""
        # This would check vulnerability scanning and patch management
        # Implementation depends on InfoBlox vulnerability management features
        pass
    
    # HIPAA specific checks
    def _check_hipaa_access_controls(self, admin_users: List[Dict], findings: List[Dict]) -> None:
        """Check HIPAA access control requirements"""
        # Check for role-based access
        users_without_roles = [user for user in admin_users if not user.get('admin_groups', [])]
        
        if users_without_roles:
            finding = self._create_finding(
                'HIPAA-001',
                'high',
                f'{len(users_without_roles)} users without defined roles',
                'HIPAA requires role-based access controls',
                {'users_without_roles': len(users_without_roles)}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_hipaa_audit_controls(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check HIPAA audit control requirements"""
        audit_controls = grid_info.get('audit_controls_enabled', False)
        
        if not audit_controls:
            finding = self._create_finding(
                'HIPAA-002',
                'high',
                'Audit controls not properly configured',
                'HIPAA requires audit controls to record access to ePHI',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_hipaa_integrity_controls(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check HIPAA integrity control requirements"""
        # This would check data integrity controls
        # Implementation depends on InfoBlox data integrity features
        pass
    
    def _check_hipaa_transmission_security(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check HIPAA transmission security requirements"""
        transmission_security = grid_info.get('transmission_security_enabled', False)
        
        if not transmission_security:
            finding = self._create_finding(
                'HIPAA-003',
                'high',
                'Transmission security not properly configured',
                'HIPAA requires protection of ePHI during transmission',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    # SOC2 specific checks
    def _check_soc2_security(self, grid_info: Dict, admin_users: List[Dict], findings: List[Dict]) -> None:
        """Check SOC2 security criteria"""
        # Check logical access controls
        if not grid_info.get('logical_access_controls', False):
            finding = self._create_finding(
                'SOC2-001',
                'high',
                'Logical access controls not properly implemented',
                'SOC2 requires logical access controls to protect against unauthorized access',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_soc2_availability(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOC2 availability criteria"""
        # Check system availability controls
        availability_controls = grid_info.get('availability_controls', False)
        
        if not availability_controls:
            finding = self._create_finding(
                'SOC2-002',
                'medium',
                'Availability controls not properly configured',
                'SOC2 requires controls to ensure system availability',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_soc2_processing_integrity(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOC2 processing integrity criteria"""
        # This would check processing integrity controls
        # Implementation depends on InfoBlox processing integrity features
        pass
    
    def _check_soc2_confidentiality(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOC2 confidentiality criteria"""
        confidentiality_controls = grid_info.get('confidentiality_controls', False)
        
        if not confidentiality_controls:
            finding = self._create_finding(
                'SOC2-003',
                'medium',
                'Confidentiality controls not properly configured',
                'SOC2 requires controls to protect confidential information',
                {}
            )
            findings.append(finding)
            self.findings.append(finding)
    
    def _check_soc2_privacy(self, grid_info: Dict, findings: List[Dict]) -> None:
        """Check SOC2 privacy criteria"""
        # This would check privacy controls if applicable
        # Implementation depends on InfoBlox privacy features
        pass
    
    # General compliance checks
    def _check_data_retention(self, grid_info: Dict) -> None:
        """Check data retention policies"""
        retention_policy = grid_info.get('data_retention_policy', False)
        
        if not retention_policy:
            self._add_finding(
                'COMP-001',
                'medium',
                'Data retention policy not configured',
                'Configure data retention policies to meet compliance requirements'
            )
    
    def _check_access_logging(self, grid_info: Dict) -> None:
        """Check access logging configuration"""
        access_logging = grid_info.get('access_logging_enabled', False)
        
        if not access_logging:
            self._add_finding(
                'COMP-002',
                'high',
                'Access logging not enabled',
                'Enable access logging for compliance audit trails'
            )
    
    def _check_change_management(self, grid_info: Dict) -> None:
        """Check change management processes"""
        change_mgmt = grid_info.get('change_management_documented', False)
        
        if not change_mgmt:
            self._add_finding(
                'COMP-003',
                'medium',
                'Change management not documented',
                'Document change management processes for compliance'
            )
    
    def _check_backup_recovery(self, grid_info: Dict) -> None:
        """Check backup and recovery procedures"""
        backup_tested = grid_info.get('backup_recovery_tested', False)
        
        if not backup_tested:
            self._add_finding(
                'COMP-004',
                'medium',
                'Backup recovery not tested',
                'Regularly test backup and recovery procedures'
            )
    
    def _create_finding(self, rule_id: str, severity: str, title: str,
                       description: str, details: Dict = None) -> Dict[str, Any]:
        """Create a compliance finding"""
        return {
            'rule_id': rule_id,
            'severity': severity,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
    
    def _add_finding(self, rule_id: str, severity: str, title: str,
                    description: str, details: Dict = None) -> None:
        """Add audit finding"""
        finding = self._create_finding(rule_id, severity, title, description, details)
        self.findings.append(finding)
        logger.warning(f"Compliance Finding [{severity.upper()}]: {title}")
    
    def _calculate_compliance_score(self, findings: List[Dict]) -> float:
        """Calculate compliance score (0-100)"""
        if not findings:
            return 100.0
        
        # Weight findings by severity
        weights = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2, 'info': 1}
        total_weight = sum(weights.get(f['severity'], 1) for f in findings)
        
        # Calculate score (higher weight = lower score)
        max_possible_weight = len(findings) * weights['critical']
        score = max(0, 100 - (total_weight / max_possible_weight * 100))
        
        return round(score, 1)
    
    def _determine_compliance_status(self, findings: List[Dict]) -> str:
        """Determine compliance status"""
        critical_count = sum(1 for f in findings if f['severity'] == 'critical')
        high_count = sum(1 for f in findings if f['severity'] == 'high')
        
        if critical_count > 0:
            return 'Non-Compliant'
        elif high_count > 3:
            return 'Partially Compliant'
        elif high_count > 0:
            return 'Mostly Compliant'
        else:
            return 'Compliant'
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate audit summary"""
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'overall_compliance_score': self._calculate_compliance_score(self.findings),
            'overall_status': self._determine_compliance_status(self.findings)
        }
