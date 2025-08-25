# InfoBlox Audit Tool

A comprehensive security and compliance audit tool for InfoBlox DNS/DHCP infrastructure. This tool provides automated assessment of InfoBlox deployments, identifying security vulnerabilities, compliance gaps, and configuration best practices.

## 🎯 Purpose

This tool is designed for defensive security purposes to help organizations:
- Identify security misconfigurations in InfoBlox DNS/DHCP systems
- Ensure compliance with industry standards and best practices
- Detect potential vulnerabilities before they can be exploited
- Generate comprehensive audit reports for security teams and management

## ✨ Features

### DNS Auditing
- **DNSSEC Validation**: Verify DNSSEC implementation and key management
- **Zone Transfer Security**: Detect unrestricted zone transfers
- **DNS Record Analysis**: Identify suspicious or malicious DNS records
- **Recursion Controls**: Validate DNS recursion restrictions
- **Cache Poisoning Protection**: Check for DNS security features

### DHCP Auditing
- **Scope Configuration**: Review DHCP scope settings and boundaries
- **Lease Management**: Analyze DHCP lease configurations
- **Reservation Security**: Audit DHCP reservations and static mappings
- **Failover Configuration**: Verify DHCP failover settings
- **Option Security**: Review DHCP options for security risks

### Security Assessment
- **Authentication & Authorization**: Review user access controls and permissions
- **Network Security**: Analyze network ACLs and firewall rules
- **SSL/TLS Configuration**: Verify secure communication settings
- **Logging & Monitoring**: Assess audit logging capabilities
- **API Security**: Review WAPI security configurations

### Compliance Reporting
- **Multiple Output Formats**: HTML, PDF, JSON, and Excel reports
- **Severity Classification**: Critical, High, Medium, and Low findings
- **Remediation Guidance**: Actionable recommendations for each finding
- **Executive Summary**: High-level overview for management
- **Technical Details**: In-depth analysis for security teams

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- InfoBlox NIOS 8.0 or later
- Network access to InfoBlox Grid Master or appliances
- Valid InfoBlox credentials with read permissions

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/InfoBloxAudit.git
cd InfoBloxAudit
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure credentials (see Configuration section below)

4. Run your first audit:
```bash
python main.py --target <infoblox-ip> --username <user> --password <pass>
```

## 📦 Project Structure

```
InfoBloxAudit/
├── src/                      # Source code
│   ├── audit/               # Audit modules
│   │   ├── dns_audit.py    # DNS configuration and security auditing
│   │   ├── dhcp_audit.py   # DHCP configuration auditing
│   │   ├── security_audit.py # Security posture assessment
│   │   └── compliance_audit.py # Compliance checking
│   ├── api/                 # API integration
│   │   └── infoblox_client.py # InfoBlox WAPI client
│   ├── reports/             # Report generation
│   │   └── report_generator.py # Multi-format report generator
│   └── utils/               # Utilities
│       └── helpers.py       # Helper functions
├── config/                   # Configuration files
│   ├── config.yaml          # Main configuration
│   └── audit_rules.yaml    # Audit rule definitions
├── tests/                    # Test suite
│   ├── test_dns_audit.py   # DNS audit tests
│   └── test_infoblox_client.py # API client tests
├── reports/                  # Generated audit reports
├── docker/                   # Docker configuration
├── requirements.txt          # Python dependencies
├── setup.py                 # Package setup
├── setup.sh                 # Setup script
└── main.py                  # Main entry point
```

## 🔧 Configuration

### Basic Configuration

Create or modify `config/config.yaml`:

```yaml
infoblox:
  host: <infoblox-ip>
  username: <username>
  password: <password>
  port: 443
  version: 2.12
  ssl_verify: true
  timeout: 30

dns_audit:
  check_zones: true
  check_records: true
  check_security: true
  check_dnssec: true

dhcp_audit:
  check_networks: true
  check_ranges: true
  check_leases: true
  check_reservations: true

security_audit:
  check_users: true
  check_permissions: true
  check_logging: true
  check_api_security: true

compliance_audit:
  frameworks:
    - CIS
    - PCI-DSS
    - HIPAA
    - SOC2

reporting:
  include_executive_summary: true
  include_technical_details: true
  include_remediation_steps: true
```

## 💻 Command Line Usage

### Basic Usage
```bash
python main.py --target <infoblox-ip> --username <user> --password <pass>
```

### Advanced Options
```bash
# Specify audit type
python main.py -t <ip> -u <user> -p <pass> --audit-type dns

# Generate specific report format
python main.py -t <ip> -u <user> -p <pass> --format pdf

# Use custom configuration
python main.py -t <ip> -u <user> -p <pass> --config custom_config.yaml

# Enable verbose output
python main.py -t <ip> -u <user> -p <pass> --verbose
```

### Available Audit Types
- `all` - Run all audit modules (default)
- `dns` - DNS configuration and security audit only
- `dhcp` - DHCP configuration audit only
- `security` - Security assessment only
- `compliance` - Compliance checking only

### Report Formats
- `html` - Interactive HTML report (default)
- `pdf` - PDF report for documentation
- `json` - JSON format for integration
- `xlsx` - Excel spreadsheet for analysis

## 📊 Understanding Audit Results

### Severity Levels
- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant security issue that should be addressed soon
- **Medium**: Moderate risk that should be planned for remediation
- **Low**: Minor issue or optimization opportunity

### Report Sections
1. **Executive Summary**: High-level overview of findings
2. **Risk Assessment**: Overall security posture evaluation
3. **Detailed Findings**: Comprehensive list of all issues
4. **Remediation Guidance**: Step-by-step fixes for each finding
5. **Compliance Mapping**: Findings mapped to compliance frameworks

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test module
pytest tests/test_dns_audit.py
```

## 🐳 Docker Support

Build and run with Docker:
```bash
# Build the image
docker build -t infoblox-audit .

# Run the audit
docker run -v $(pwd)/reports:/app/reports infoblox-audit \
  --target <infoblox-ip> --username <user> --password <pass>
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and enhancement requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Security Notice

This tool is designed for **defensive security purposes only**. It should be used to:
- Audit your own InfoBlox infrastructure
- Identify security misconfigurations in authorized systems
- Improve security posture of managed environments

**Do not use this tool on systems you do not own or have explicit permission to audit.**

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- InfoBlox for providing comprehensive API documentation
- The security community for continuous improvement suggestions
- Contributors who help make this tool better

## 📧 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact the security team
- Review the documentation wiki
