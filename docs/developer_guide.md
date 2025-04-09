# Port Mapper Developer Guide

This document provides comprehensive information for developers working on the Port Mapper application. It covers the codebase architecture, key components, data flow, and development procedures.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Key Functions & Features](#key-functions--features)
5. [Important Algorithms](#important-algorithms)
6. [Port Mapping System](#port-mapping-system)
7. [Test Suite](#test-suite)
8. [Common Issues & Solutions](#common-issues--solutions)
9. [Development Workflow](#development-workflow)
10. [Deployment](#deployment)

## Architecture Overview

Port Mapper is a Flask web application that processes CSV files to generate firewall port mapping requests. The application:

1. Accepts CSV uploads with server information
2. Processes the CSV to extract hostname, IP, and exporter information
3. Identifies standard servers and edge cases (blackbox monitoring)
4. Provides an interface for customizing port configurations
5. Generates firewall rules in various output formats

### Technology Stack

- **Backend**: Python 3.6+ with Flask web framework
- **Frontend**: HTML, CSS, JavaScript (vanilla JS, no framework)
- **Data Processing**: pandas, csv module
- **Configuration**: YAML
- **Output Formats**: CSV, Excel, PDF, custom firewall formats
- **Container**: Docker for deployment
- **CI/CD**: GitHub Actions for testing and Docker image building

## Core Components

### 1. Flask Application (app.py)

The main application file containing all routes, request handlers, and core processing logic.

### 2. Configuration System

- **port_defaults.py**: Contains fallback default port mappings if no configuration file is found
- **config_loader.py**: Handles loading and parsing YAML configuration files

### 3. Templates

- **index.html**: The home page with CSV upload form
- **process.html**: The server selection and port configuration page
- **pdf_template.html**: Template for PDF output generation

### 4. Static Assets

- CSS styling and background images

### 5. Support Scripts

- **firewall_check.sh**: Bash script for testing port connectivity

## Data Flow

### 1. CSV Upload Flow

1. User uploads a CSV file with server data via the home page form
2. The file is saved to a temporary location
3. File path and MaaS-NG information are stored in the session
4. User is redirected to the process page

### 2. Processing Flow

1. Process page reads the uploaded CSV file
2. Headers are identified using flexible detection
3. Each row is processed to extract hostname, IP, and exporter information
4. For each server:
   - Exporter columns are identified
   - Blackbox monitoring flags are detected (ssh-banner, tcp-connect, etc.)
   - Edge cases (servers with monitoring flags but no exporters) are identified
   - Suggested port mappings are determined based on exporter types

### 3. Port Configuration Flow

1. User selects servers and configures custom ports if needed
2. Form is submitted to the generate_output_csv endpoint
3. Selected servers and port configurations are processed
4. Output file is generated in the selected format
5. Output file is sent to the user for download

## Key Functions & Features

### CSV Processing

- **Flexible Header Detection**: Scans the first 10 rows to find headers
- **Case-Insensitive Column Matching**: Headers are matched case-insensitively
- **Blackbox Monitoring Detection**: Special monitoring flags are detected with various formats (TRUE/True/true)

### Port Configuration

- **Exporter-Specific Port Settings**: Each exporter can have custom port configurations
- **Blackbox Monitoring Ports**: Special monitoring types have appropriate default ports
- **Port Validation**: Client-side validation ensures valid port formats
- **Hybrid Support**: Servers with both exporters and monitoring flags are handled correctly

### Output Generation

- **Multiple Formats**: CSV, Excel, PDF, and firewall-specific formats
- **Firewall Check Format**: Special format for port connectivity testing
- **Duplicate Detection**: Prevents duplicate port entries in the output

## Important Algorithms

### Edge Case Detection

The application identifies edge cases (servers with monitoring flags but no standard exporters) by:

1. Checking for exporter columns
2. If no exporters are found, checking for monitoring flags
3. Marking as edge case if at least one monitoring flag is present

The key code for this is in the `process` function in app.py:

```python
# Check for exporters
for idx in exporter_indices:
    if idx < len(row) and row[idx].strip():
        has_exporters = True
        break

# Always check monitoring flags, even for servers with exporters (hybrid case)
# Only mark as edge case if it has no exporters

# Check SSH Banner
if ssh_banner_index is not None and ssh_banner_index < len(row):
    orig_value = row[ssh_banner_index].strip()
    value = orig_value.lower()
    if value in ('1', 'true', 'yes', 'y', 't'):
        monitoring_flags['ssh_banner'] = orig_value  # Keep original value
        if not has_exporters:
            is_edge_case = True
        logger.info(f"Detected SSH Banner for {row[fqdn_index]}: {orig_value}")
```

### Blackbox Monitoring Flag Detection

The application supports multiple formats for boolean flags:

1. Case-insensitive string values: "TRUE", "True", "true"
2. Abbreviated forms: "T", "t", "Y", "y"
3. Numeric values: "1"
4. Alternative terms: "yes", "YES", "Yes"

These are detected using a case-insensitive comparison:

```python
value = row[ssh_banner_index].strip().lower()
if value in ('1', 'true', 'yes', 'y', 't'):
    monitoring_flags['ssh_banner'] = True
    is_edge_case = True
```

### Port Conflict Resolution

When custom port fields contain boolean values like "TRUE" instead of port numbers, the application:

1. Checks if the port value is a boolean flag
2. If so, uses default ports or values from the TCP_Connect_Port column
3. Otherwise, uses the custom port value

```python
port = form_data[tcp_connect_port_key][0].strip()
if port and port.lower() not in ('true', 'yes', '1', 't', 'y'):
    blackbox_ports.append(("TCP", port, "TCP Connect"))
else:
    # Default or from TCP_Connect_Port
    port = tcp_port_value or "3389"
    blackbox_ports.append(("TCP", port, "TCP Connect"))
```

## Port Mapping System

### Configuration Structure

Port mappings have a standard format in both code and YAML:

```yaml
exporter_linux:
  src:  # Source (monitoring server) to target ports
    - ["TCP", "22"]
    - ["ICMP", "ping"]
  dst:  # Destination (target) back to monitoring server ports
    []
```

### Custom Port Mapping

The application supports session-based custom port mappings:

1. Users can add new exporters in the Port Mappings tab
2. Custom mappings are stored both in localStorage (client-side) and in the session (server-side)
3. These mappings are merged with the defaults during CSV generation

### Default Port Assignment

For blackbox monitoring, standard default ports are used:

- SSH Banner: TCP port 22
- TCP Connect: TCP port 3389 (or custom value from TCP_Connect_Port)
- SNMP: UDP port 161 (inbound) and UDP port 162 (outbound)
- SSL: TCP port 443

## Test Suite

The application includes a comprehensive test suite that verifies:

1. Basic functionality (file upload, page rendering)
2. CSV processing
3. Edge case detection
4. Port configuration handling
5. Output generation
6. API endpoints

### Running Tests

```bash
# Run all tests with coverage
pytest test_app.py test_app_coverage.py --cov=app --cov-report=term

# Run specific tests
pytest test_app.py::test_edge_case_detection -v
```

### Adding New Tests

When adding new features, always add corresponding tests that:

1. Verify the basic functionality
2. Test edge cases and error conditions
3. Ensure backward compatibility

## Common Issues & Solutions

### "TRUE" as Port Value

The application previously had an issue where it would use "TRUE" as a port value when a boolean flag was in the port field. This is now fixed by:

1. Detecting boolean values in port fields
2. Using default ports when boolean values are found

### Form Validation Issues

Client-side validation in process.html needs to handle:

1. Numeric ports (e.g., "22", "443")
2. Special port values like "ping"
3. Boolean values like "TRUE", "true", "yes"

The current implementation in validateSelection() uses pattern matching to validate port inputs.

### Duplicate Port Entries

To prevent duplicate entries in the output:

1. A unique_entries set tracks all entries that have been added
2. Before adding an entry, it's checked against this set
3. Custom port entries are filtered against blackbox monitoring entries

## Development Workflow

### Setting Up a Development Environment

```bash
# Clone the repository
git clone https://github.com/Brownster/portmapper.git
cd portmapper

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Making Changes

1. Create a new branch for your feature or fix
2. Make your changes
3. Run tests to ensure nothing is broken
4. Update documentation if necessary
5. Run Python linting to maintain code quality
6. Submit a pull request

### Code Style

The project follows these style guidelines:

- PEP 8 for Python code
- 4 spaces for indentation
- Function and variable names in snake_case
- Constants in UPPER_SNAKE_CASE
- Docstrings for all functions and classes
- Detailed comments for complex logic

## Deployment

### Docker Deployment

The simplest way to deploy the application is using Docker:

```bash
# Pull the latest image
docker pull brownster/portmapper:latest

# Run the container
docker run -p 5000:5000 brownster/portmapper:latest
```

### Custom Configuration

To use a custom configuration:

```bash
# With Docker
docker run -p 5000:5000 -v /path/to/custom_config.yaml:/app/port_config.yaml brownster/portmapper:latest

# Without Docker
export PORT_CONFIG=/path/to/custom_config.yaml
python app.py
```

### Integration with Reverse Proxy

For production deployment, consider using a reverse proxy like Nginx:

```nginx
server {
    listen 80;
    server_name portmapper.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Docker Documentation](https://docs.docker.com/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

## Appendix: Core Function Reference

### app.py Functions

| Function | Description |
|----------|-------------|
| `create_port_csv()` | Core function for generating port mappings from CSV data |
| `process()` | Handles processing the uploaded CSV and rendering the selection page |
| `generate_output_csv()` | Processes form submission and redirects to output generation |
| `process_and_generate_output()` | Generates output in the selected format |
| `find_edge_cases()` | Legacy function (replaced by inline processing) |
| `generate_firewall_check_csv()` | Creates the special firewall check CSV format |
| `generate_firewall_script()` | Generates firewall-specific configuration formats |
| `port_mappings_api()` | API endpoint for managing port mappings |