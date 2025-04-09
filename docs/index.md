# Port Mapper Documentation

Welcome to the Port Mapper documentation. This documentation is intended for developers, administrators, and users of the Port Mapper application.

## Overview

Port Mapper is a Flask-based web application that automates the generation of firewall requests from uploaded CSV files. It parses network configurations from CSV files, matches them against predefined or custom port mappings, and generates detailed firewall rules in various formats.

## Documentation Index

### User Documentation
- [README.md](../README.md) - Overview, features, installation, and basic usage instructions
- [Troubleshooting Guide](troubleshooting.md) - Solutions to common issues

### Developer Documentation
- [Developer Guide](developer_guide.md) - Comprehensive information for developers
- [Technical Architecture](architecture.md) - System components and interactions
- [API Documentation](api.md) - API endpoints and usage (Coming soon)

## Quick Links

### Installation

```bash
# Using Docker (recommended)
docker pull brownster/portmapper:latest
docker run -p 5000:5000 brownster/portmapper:latest

# Manual Installation
git clone https://github.com/Brownster/portmapper.git
cd portmapper
pip install -r requirements.txt
python app.py
```

### Key Features

- CSV upload and processing
- Flexible header detection
- Blackbox monitoring support (SSH-banner, TCP-connect, SNMP, SSL)
- Custom port configuration
- Multiple output formats (CSV, Excel, PDF, firewall-specific)
- Port mappings management interface

### Configuration

Port mappings can be configured via:
- YAML configuration file
- Web interface (Port Mappings tab)
- Environment variables

### Testing

```bash
pytest test_app.py test_app_coverage.py --cov=app --cov-report=term
```

## Contributing

Contributions to both the code and documentation are welcome. Please follow the guidelines in the [README.md](../README.md#contributing) file.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.