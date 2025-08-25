# Contributing to InfoBlox Audit Tool

Thank you for your interest in contributing to the InfoBlox Audit Tool! This document provides guidelines and instructions for contributing to this defensive security project.

## Code of Conduct

This project is designed for **defensive security purposes only**. All contributions must align with this principle:
- Code must help identify and remediate security issues
- Features must support defensive security operations
- No contributions that could enable malicious use will be accepted

## How to Contribute

### Reporting Issues

1. **Security Vulnerabilities**: Please report security vulnerabilities privately to the maintainers
2. **Bugs**: Use the GitHub issue tracker with the "bug" label
3. **Feature Requests**: Use the GitHub issue tracker with the "enhancement" label

### Development Process

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/InfoBloxAudit.git
   cd InfoBloxAudit
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set Up Development Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e .
   ```

4. **Make Your Changes**
   - Follow the existing code style and structure
   - Add appropriate error handling
   - Update documentation as needed
   - Write tests for new functionality

5. **Run Tests**
   ```bash
   # Run all tests
   pytest
   
   # Run with coverage
   pytest --cov=src --cov-report=html
   
   # Run linting
   flake8 src/
   black src/ --check
   mypy src/
   ```

6. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add new audit check for X"
   ```
   
   Follow conventional commit format:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `test:` Test additions or changes
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks

7. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 guidelines
- Use type hints for function parameters and returns
- Maximum line length: 100 characters
- Use descriptive variable and function names

### Adding New Audit Checks

When adding new audit checks, follow this structure:

```python
def _check_new_vulnerability(self, data: Dict) -> None:
    """
    Check for specific vulnerability
    
    Args:
        data: Configuration data to check
    """
    # Implement check logic
    if vulnerability_found:
        self._add_finding(
            rule_id='NEW-001',
            severity='high',  # critical, high, medium, low
            title='Clear description of the issue',
            description='Detailed explanation and remediation steps',
            details={'specific': 'context'}
        )
```

### Security Considerations

- Never log sensitive information (passwords, keys, tokens)
- Validate all input data
- Use secure defaults
- Follow principle of least privilege
- Document security implications of changes

### Testing Requirements

All new features must include:

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test interaction with InfoBlox API (mocked)
3. **Edge Cases**: Test error conditions and boundary cases

Example test structure:

```python
import pytest
from unittest.mock import Mock, patch

def test_new_audit_check():
    """Test new audit check functionality"""
    # Arrange
    client = Mock()
    audit = YourAudit(client, {})
    
    # Act
    results = audit.run()
    
    # Assert
    assert 'expected_finding' in results['findings']
```

## Documentation

### Update Documentation For:

- New command-line options in README.md
- New configuration options in config examples
- New audit checks in the appropriate module docstrings
- API changes in relevant docstrings

### Documentation Style

- Use clear, concise language
- Include code examples where appropriate
- Explain security implications
- Provide remediation guidance for findings

## Pull Request Process

1. **Before Submitting**:
   - Ensure all tests pass
   - Update documentation
   - Run linting and formatting tools
   - Test against a real InfoBlox instance if possible

2. **PR Description Should Include**:
   - Purpose of the changes
   - Any security implications
   - Testing performed
   - Related issues (use "Fixes #123" format)

3. **Review Process**:
   - At least one maintainer review required
   - All CI checks must pass
   - Security review for significant changes

## Adding New Audit Modules

To add a new audit module:

1. Create new file in `src/audit/`
2. Inherit from base audit class
3. Implement required methods
4. Add to main.py audit type options
5. Update configuration schema
6. Add comprehensive tests
7. Update documentation

## Questions?

If you have questions about contributing:
- Check existing issues and discussions
- Open a new discussion for general questions
- Contact maintainers for security-related questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.