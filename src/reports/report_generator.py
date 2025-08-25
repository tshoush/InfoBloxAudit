"""
Report Generator Module
Generates comprehensive audit reports in various formats
"""

import logging
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template

from utils.helpers import sanitize_filename, format_timestamp

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate audit reports in multiple formats"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize report generator
        
        Args:
            config: Report generation configuration
        """
        self.config = config
        self.template_dir = Path(__file__).parent / 'templates'
        self.template_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def generate_report(self, audit_results: Dict[str, Any], 
                       output_dir: str, format_type: str) -> str:
        """
        Generate audit report in specified format
        
        Args:
            audit_results: Combined audit results from all modules
            output_dir: Output directory for reports
            format_type: Report format (html, pdf, json, xlsx)
            
        Returns:
            Path to generated report file
        """
        logger.info(f"Generating {format_type.upper()} report...")
        
        # Ensure output directory exists
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process audit results
        processed_results = self._process_audit_results(audit_results)
        
        # Generate report based on format
        if format_type == 'html':
            return self._generate_html_report(processed_results, output_path, timestamp)
        elif format_type == 'json':
            return self._generate_json_report(processed_results, output_path, timestamp)
        elif format_type == 'xlsx':
            return self._generate_excel_report(processed_results, output_path, timestamp)
        elif format_type == 'pdf':
            return self._generate_pdf_report(processed_results, output_path, timestamp)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")
    
    def _process_audit_results(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and enrich audit results for reporting"""
        
        # Combine all findings
        all_findings = []
        audit_summaries = {}
        
        for audit_type, results in audit_results.items():
            if isinstance(results, dict) and 'findings' in results:
                findings = results['findings']
                for finding in findings:
                    finding['audit_type'] = audit_type
                    all_findings.append(finding)
                
                audit_summaries[audit_type] = results.get('summary', {})
        
        # Calculate overall statistics
        severity_counts = {}
        for finding in all_findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_overall_risk_score(all_findings)
        
        # Group findings by severity and audit type
        findings_by_severity = self._group_findings_by_severity(all_findings)
        findings_by_audit_type = self._group_findings_by_audit_type(all_findings)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            all_findings, severity_counts, risk_score
        )
        
        return {
            'metadata': {
                'report_generated': format_timestamp(),
                'total_findings': len(all_findings),
                'risk_score': risk_score,
                'audit_types': list(audit_results.keys())
            },
            'executive_summary': executive_summary,
            'severity_counts': severity_counts,
            'findings_by_severity': findings_by_severity,
            'findings_by_audit_type': findings_by_audit_type,
            'audit_summaries': audit_summaries,
            'all_findings': all_findings,
            'raw_results': audit_results
        }
    
    def _generate_html_report(self, data: Dict[str, Any], 
                             output_path: Path, timestamp: str) -> str:
        """Generate HTML report"""
        
        template = self.jinja_env.get_template('audit_report.html')
        html_content = template.render(data=data)
        
        filename = f"infoblox_audit_report_{timestamp}.html"
        file_path = output_path / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {file_path}")
        return str(file_path)
    
    def _generate_json_report(self, data: Dict[str, Any], 
                             output_path: Path, timestamp: str) -> str:
        """Generate JSON report"""
        
        filename = f"infoblox_audit_report_{timestamp}.json"
        file_path = output_path / filename
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {file_path}")
        return str(file_path)
    
    def _generate_excel_report(self, data: Dict[str, Any], 
                              output_path: Path, timestamp: str) -> str:
        """Generate Excel report"""
        
        filename = f"infoblox_audit_report_{timestamp}.xlsx"
        file_path = output_path / filename
        
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            # Executive Summary sheet
            summary_data = {
                'Metric': ['Total Findings', 'Risk Score', 'Critical Issues', 'High Issues', 'Medium Issues', 'Low Issues'],
                'Value': [
                    data['metadata']['total_findings'],
                    data['metadata']['risk_score'],
                    data['severity_counts'].get('critical', 0),
                    data['severity_counts'].get('high', 0),
                    data['severity_counts'].get('medium', 0),
                    data['severity_counts'].get('low', 0)
                ]
            }
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Executive Summary', index=False)
            
            # All Findings sheet
            if data['all_findings']:
                findings_df = pd.DataFrame(data['all_findings'])
                findings_df.to_excel(writer, sheet_name='All Findings', index=False)
            
            # Findings by Audit Type
            for audit_type, findings in data['findings_by_audit_type'].items():
                if findings:
                    df = pd.DataFrame(findings)
                    sheet_name = sanitize_filename(audit_type)[:31]  # Excel sheet name limit
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        logger.info(f"Excel report generated: {file_path}")
        return str(file_path)
    
    def _generate_pdf_report(self, data: Dict[str, Any], 
                            output_path: Path, timestamp: str) -> str:
        """Generate PDF report (requires additional dependencies)"""
        
        # For now, generate HTML and suggest PDF conversion
        html_path = self._generate_html_report(data, output_path, timestamp)
        
        logger.warning("PDF generation requires additional dependencies. HTML report generated instead.")
        logger.info("To convert to PDF, use: wkhtmltopdf or similar tool")
        
        return html_path
    
    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity level"""
        grouped = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        
        # Sort by severity order
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        ordered_grouped = {}
        for severity in severity_order:
            if severity in grouped:
                ordered_grouped[severity] = grouped[severity]
        
        return ordered_grouped
    
    def _group_findings_by_audit_type(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by audit type"""
        grouped = {}
        for finding in findings:
            audit_type = finding.get('audit_type', 'unknown')
            if audit_type not in grouped:
                grouped[audit_type] = []
            grouped[audit_type].append(finding)
        
        return grouped
    
    def _calculate_overall_risk_score(self, findings: List[Dict]) -> int:
        """Calculate overall risk score"""
        if not findings:
            return 0
        
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        total_weight = sum(weights.get(f.get('severity', 'low'), 1) for f in findings)
        
        # Normalize to 0-100 scale
        max_possible = len(findings) * weights['critical']
        risk_score = min(100, (total_weight / max_possible) * 100) if max_possible > 0 else 0
        
        return int(risk_score)
    
    def _generate_executive_summary(self, findings: List[Dict], 
                                   severity_counts: Dict[str, int], 
                                   risk_score: int) -> Dict[str, Any]:
        """Generate executive summary"""
        
        # Determine overall risk level
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Top issues by severity
        critical_issues = [f for f in findings if f.get('severity') == 'critical']
        high_issues = [f for f in findings if f.get('severity') == 'high']
        
        # Key recommendations
        recommendations = []
        if critical_issues:
            recommendations.append("Immediately address all critical security issues")
        if high_issues:
            recommendations.append("Prioritize resolution of high-severity findings")
        if severity_counts.get('medium', 0) > 10:
            recommendations.append("Develop remediation plan for medium-severity issues")
        
        return {
            'total_findings': len(findings),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'severity_breakdown': severity_counts,
            'critical_count': len(critical_issues),
            'high_count': len(high_issues),
            'top_critical_issues': critical_issues[:5],  # Top 5 critical issues
            'top_high_issues': high_issues[:5],  # Top 5 high issues
            'key_recommendations': recommendations
        }
    
    def _create_default_templates(self) -> None:
        """Create default HTML template if it doesn't exist"""
        
        template_path = self.template_dir / 'audit_report.html'
        
        if not template_path.exists():
            html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InfoBlox Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .critical { border-left-color: #d32f2f; background-color: #ffebee; }
        .high { border-left-color: #f57c00; background-color: #fff3e0; }
        .medium { border-left-color: #fbc02d; background-color: #fffde7; }
        .low { border-left-color: #388e3c; background-color: #e8f5e8; }
        .info { border-left-color: #1976d2; background-color: #e3f2fd; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>InfoBlox Security Audit Report</h1>
        <p><strong>Generated:</strong> {{ data.metadata.report_generated }}</p>
        <p><strong>Total Findings:</strong> {{ data.metadata.total_findings }}</p>
        <p><strong>Risk Score:</strong> {{ data.metadata.risk_score }}/100</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> {{ data.executive_summary.risk_level }}</p>
        
        <h3>Findings by Severity</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {% for severity, count in data.severity_counts.items() %}
            <tr><td>{{ severity.title() }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
    </div>

    {% for severity, findings in data.findings_by_severity.items() %}
    <div class="findings-section">
        <h2>{{ severity.title() }} Findings ({{ findings|length }})</h2>
        {% for finding in findings %}
        <div class="finding {{ severity }}">
            <h4>{{ finding.title }}</h4>
            <p><strong>Rule ID:</strong> {{ finding.rule_id }}</p>
            <p><strong>Description:</strong> {{ finding.description }}</p>
            <p><strong>Audit Type:</strong> {{ finding.audit_type }}</p>
            {% if finding.details %}
            <p><strong>Details:</strong> {{ finding.details }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endfor %}
</body>
</html>'''
            
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            logger.info(f"Created default HTML template: {template_path}")
