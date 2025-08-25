# InfoBlox Audit Tool

A comprehensive audit tool for InfoBlox DNS/DHCP systems that helps organizations assess their InfoBlox infrastructure for security, compliance, and operational best practices.

## Features

- **DNS Configuration Audit**: Analyze DNS zones, records, and security settings
- **DHCP Configuration Review**: Examine DHCP scopes, reservations, and policies
- **Security Assessment**: Check for security vulnerabilities and misconfigurations
- **Compliance Reporting**: Generate reports for various compliance frameworks
- **Performance Analysis**: Identify performance bottlenecks and optimization opportunities
- **Change Detection**: Track configuration changes over time

## Quick Start

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure your InfoBlox credentials in `config/config.yaml`
4. Run the audit: `python main.py --target <infoblox-ip>`

## Project Structure

```
InfoBloxAudit/
├── src/
│   ├── audit/
│   │   ├── dns_audit.py
│   │   ├── dhcp_audit.py
│   │   ├── security_audit.py
│   │   └── compliance_audit.py
│   ├── api/
│   │   └── infoblox_client.py
│   ├── reports/
│   │   └── report_generator.py
│   └── utils/
│       └── helpers.py
├── config/
│   ├── config.yaml
│   └── audit_rules.yaml
├── tests/
├── reports/
├── docker/
├── requirements.txt
├── main.py
└── setup.py
```

## Requirements

- Python 3.8+
- InfoBlox NIOS 8.0+
- Network access to InfoBlox appliances

## License

MIT License
