# Port Mapper - Firewall Request Generator

[![Test, Build and Push Docker image](https://github.com/Brownster/portmapper.py/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Brownster/portmapper.py/actions/workflows/docker-image.yml)
[![Pylint & Testing](https://github.com/Brownster/portmapper.py/actions/workflows/pylint.yml/badge.svg)](https://github.com/Brownster/portmapper.py/actions/workflows/pylint.yml)
[![Coverage](https://github.com/Brownster/portmapper.py/raw/main/.github/badges/coverage.svg)](https://github.com/Brownster/portmapper.py/actions/workflows/coverage-badge.yml)

This Flask application automates the generation of firewall requests from uploaded CSV files. It parses specific network configurations from the CSV, matches them against a predefined set of exporter configurations, and outputs a new CSV with detailed firewall rules.

## Features

- **CSV Upload**: Users can upload CSV files containing details about network endpoints.
- **Rule Mapping**: Maps incoming and outgoing rules based on configurations defined in YAML files.
- **FQDN and IP Handling**: Handles both Fully Qualified Domain Names (FQDN) and IP addresses to specify sources and destinations.
- **Secure File Handling**: Temporarily stores uploaded files in a secure manner and cleans up old files regularly.
- **Edge Case Support**: Automatically detects and allows configuration of servers with special monitoring flags but no standard exporters.
- **Smart Port Suggestions**: Suggests appropriate ports based on monitoring types (SSH Banner, TCP Connect, SNMP, SSL).
- **Custom Port Configuration**: Allows customization of port mappings for all targets through an intuitive interface, not just edge cases.
- **Exporter-Specific Port Settings**: Configure ports for specific exporters on a per-server basis.
- **Blackbox Monitoring Fields**: Support for SSH-banner, TCP-connect, SNMP, and SSL monitoring with customizable ports.
- **Multiple Output Formats**: Supports CSV, Excel, PDF, and firewall-specific formats (Cisco ASA, Juniper SRX, Palo Alto, iptables).
- **Firewall Check Tool**: Generate a specialized CSV containing only monitoring-to-target entries and use the included shell script to verify port connectivity.
- **User Feedback**: Provides user feedback via flash messages for file upload success or failure.
- **Configurable Port Mappings**: Port mappings and column names are configurable via YAML configuration file, making it easy to adapt to different environments.

![image](https://github.com/user-attachments/assets/da18ab5d-61aa-47ce-ae8e-1635b3f2f884)

![image](https://github.com/user-attachments/assets/46223b80-dd74-4cf9-9ae4-291d55b1dd62)

![image](https://github.com/user-attachments/assets/4b98f4fd-7c38-4403-bcca-4d9b4be28ffa)


Here is a breakdown of the required CSV file fields mentioned in your script:

    FQDN: Fully Qualified Domain Name of the target server. This field is crucial as it is used to match the target server in the firewall rule entries.
    IP Address: The IP address of the target server. Like the FQDN, it is used to specify the source or destination IP in firewall rules.
    Exporter_name_os: This field appears to indicate the operating system or platform specific exporter configurations, which determine what ports and protocols are allowed for source communications.
    Exporter_name_app: Application-specific exporter configurations, detailing the ports and protocols used for destination communications.

These fields are utilized in the script to determine the rule mappings and to generate the necessary firewall configurations. When you create a CSV file for upload, each record should at least include these columns to ensure the script can process it correctly.
## CSV File Format

Your CSV files should include the following columns:

- `FQDN` - The Fully Qualified Domain Name of the target server
- `IP Address` - The IP address of the target server
- One or more exporter columns (e.g., `Exporter_name_os`, `Exporter_name_app`)

### Edge Case Monitoring Flags

The app also supports special monitoring flags for servers without standard exporters:

- `ssh-banner` - For SSH banner monitoring (default port: 22)
- `tcp-connect` - For TCP connectivity monitoring (default port: 3389)
- `TCP_Connect_Port` - For custom TCP port monitoring (specify the port number directly)
- `SNMP` - For SNMP monitoring (default ports: 161 inbound, 162 outbound)
- `Exporter_SSL` - For SSL certificate monitoring (default port: 443)

Example CSV structure:

```
FQDN,IP Address,Exporter_name_os,Exporter_name_app,Exporter_name_app_2,Exporter_name_app_3,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,,, 
server2.example.com,192.168.1.11,exporter_windows,exporter_mpp,,,,,,,
db1.example.com,192.168.1.20,exporter_linux,exporter_redis,,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,,,8080,,true
```

Note that servers with empty exporter columns but with monitoring flags set (like blackbox1 and blackbox2) will be detected as edge cases, allowing for custom port configuration.

### Flexible CSV Handling

The application is designed to be flexible with CSV formats:

- Headers don't need to be on the first line (will scan the first 10 lines)
- Column names are case-insensitive
- Any column with "FQDN" in its name will be recognized as the FQDN column
- Any column with "IP" and "Address" in its name will be recognized as the IP Address column
- Any column with "Exporter" in its name will be recognized as an exporter column

This means the tool can handle various Excel export formats where headers might start on line 5, 6, or 7, and column names might vary slightly.


Tips for CSV File Preparation

    Consistency: Ensure that the column headers in your CSV files match exactly with the field identifiers expected by the script. This includes maintaining the same case and spelling.
    Validation: Validate the data in each column to ensure that IP addresses are properly formatted, FQDNs are valid, and exporter names correspond to those defined in your port mappings.

PORT MAPPINGS
    define the prometheus exporter src is from the monitoring server to the target and dst is from target server to monitoring server

    port_mappings = {
        "exporter_aes": {
            "src": [("TCP", "22"), ("TCP", "443")],
            "dst": [("UDP", "514"), ("TCP", "514"), ("UDP", "162")],
        },

EXAMPLE INPUT CSV AND OUTPUT CSV:
FQDN,IP Address,Exporter_name_os,Exporter_name_app
server1.example.com,192.168.1.10,exporter_linux,exporter_iq
server2.example.com,192.168.1.11,exporter_windows,exporter_aacc
server3.example.com,192.168.1.12,exporter_vmware,exporter_breeze

This CSV contains the necessary information about several servers, specifying both the operating system and application-specific firewall rule settings.
## Output Formats

The application supports multiple output formats:

### Standard CSV Output

Based on the input data and the provided exporter configurations, the standard CSV output lists detailed firewall rules needed for each server. For simplicity, let's say the Monitoring Server IP is 10.10.10.10 and its FQDN is monitor.example.com.

```
Source_FQDN,Source_IP_Address,Destination_FQDN,Destination_IP_Address,Proto,Port,Description
monitor.example.com,10.10.10.10,server1.example.com,192.168.1.10,TCP,22,"Monitoring from monitor.example.com to server1.example.com (exporter_linux)"
monitor.example.com,10.10.10.10,server1.example.com,192.168.1.10,ICMP,ping,"Monitoring from monitor.example.com to server1.example.com (exporter_linux)"
monitor.example.com,10.10.10.10,blackbox1.example.com,192.168.1.30,TCP,22,"Monitoring from monitor.example.com to blackbox1.example.com (edge case)"
monitor.example.com,10.10.10.10,blackbox1.example.com,192.168.1.30,UDP,161,"Monitoring from monitor.example.com to blackbox1.example.com (edge case)"
blackbox1.example.com,192.168.1.30,monitor.example.com,10.10.10.10,UDP,162,"Return traffic from blackbox1.example.com to monitor.example.com (edge case)"
```

### Firewall Check CSV

A specialized format that contains only monitoring server to target entries for port connectivity testing:

```
Target_FQDN,Target_IP,Protocol,Port,Status
server1.example.com,192.168.1.10,TCP,22,
server1.example.com,192.168.1.10,ICMP,ping,
blackbox1.example.com,192.168.1.30,TCP,22,
blackbox1.example.com,192.168.1.30,UDP,161,
```

The Status column is left empty for the shell script to fill in with connectivity test results.

### Firewall Configuration Formats

The application can also generate firewall-specific configuration formats:

#### Cisco ASA Format
```
! Cisco ASA Firewall Rules
! Generated on 2025-05-04 08:15:22
! For MaaS-NG server: monitor.example.com (10.10.10.10)
!
access-list MAAS-MONITORING extended permit tcp host 10.10.10.10 host 192.168.1.10 eq 22 ! Monitoring from monitor.example.com to server1.example.com (exporter_linux)
access-list MAAS-MONITORING extended permit icmp host 10.10.10.10 host 192.168.1.10 ! Monitoring from monitor.example.com to server1.example.com (exporter_linux)
!
! End of generated rules
! Total rules: 5
```

#### Juniper SRX Format
```
# Juniper SRX Security Policy
# Generated on 2025-05-04 08:15:22
# For MaaS-NG server: monitor.example.com (10.10.10.10)
#
set applications {
    application maas-TCP-22 protocol tcp destination-port 22
    application maas-ICMP-ping protocol icmp
}

set security policies from-zone trust to-zone untrust policy MAAS-1 match source-address 10.10.10.10/32
set security policies from-zone trust to-zone untrust policy MAAS-1 match destination-address 192.168.1.10/32
set security policies from-zone trust to-zone untrust policy MAAS-1 match application maas-TCP-22
set security policies from-zone trust to-zone untrust policy MAAS-1 then permit
set security policies from-zone trust to-zone untrust policy MAAS-1 then log session-init session-close
```

#### Linux iptables Format
```bash
#!/bin/bash
# iptables rules for MaaS-NG monitoring
# Generated on 2025-05-04 08:15:22
# For MaaS-NG server: monitor.example.com (10.10.10.10)

# Flush existing rules
iptables -F MAAS-MONITORING 2>/dev/null || iptables -N MAAS-MONITORING
iptables -F MAAS-MONITORING

# Add monitoring rules
iptables -A MAAS-MONITORING -p tcp -s 10.10.10.10/32 -d 192.168.1.10/32 --dport 22 -j ACCEPT # Monitoring from monitor.example.com to server1.example.com (exporter_linux)
iptables -A MAAS-MONITORING -p icmp -s 10.10.10.10/32 -d 192.168.1.10/32 -j ACCEPT # Monitoring from monitor.example.com to server1.example.com (exporter_linux)

# Link chain to INPUT and FORWARD chains
iptables -A INPUT -j MAAS-MONITORING
iptables -A FORWARD -j MAAS-MONITORING

echo "Applied 5 MAAS monitoring rules"
```

### Other Formats
The application also supports Excel and PDF output formats for better visualization and sharing.

## Firewall Check Script

The application includes a shell script (`firewall_check.sh`) that can be used to test the connectivity to the target servers using the Firewall Check CSV format:

1. Generate a Firewall Check CSV from the application by selecting the "Firewall Check CSV" output format
2. Download the `firewall_check.sh` script from the application's main page
3. Run the script with the CSV file:

```bash
./firewall_check.sh /path/to/firewall_check.csv
```

The script will:
- Parse the CSV file
- Test connectivity to each target using the specified protocol and port
- Update the Status column with OPEN or CLOSED
- Generate a results file with the timestamp (e.g., `firewall_check_results_20250504_0815.csv`)



## Prerequisites

Before you can run this application, you'll need the following installed:
- Python 3.6 or higher
- Flask
- Werkzeug (usually installed with Flask)
- Pandas (for data manipulation)
- wkhtmltopdf (for PDF generation - optional but recommended)

### Installing wkhtmltopdf

To enable PDF generation, you need to install wkhtmltopdf:

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install wkhtmltopdf
```

#### Red Hat/CentOS/Fedora:
```bash
sudo dnf install wkhtmltopdf
# or for older systems
sudo yum install wkhtmltopdf
```

#### macOS:
```bash
brew install wkhtmltopdf
```

#### Windows:
Download and install from the [official website](https://wkhtmltopdf.org/downloads.html)

## Configuration

The application now supports configuration via YAML files. The default configuration file is `port_config.yaml` in the root directory of the project.

### Port Configuration

Port mappings and column names are defined in the YAML configuration file:

```yaml
# Column mapping configuration
column_mappings:
  exporter_os:
    column_name: "exporter_os"  # Single column to check
  
  exporter_avayasbc:
    column_names:             # Multiple columns to check
      - "exporter_app"
      - "exporter_app_2"
      - "exporter_app_3"

# Port mapping configurations
port_mappings:
  exporter_linux:
    src:  # Source (monitoring server) to target ports
      - ["TCP", "22"]
      - ["ICMP", "ping"]
    dst:  # Destination (target) back to monitoring server ports
      []
  
  exporter_windows:
    src:
      - ["TCP", "9182"]
      - ["ICMP", "ping"]
    dst:
      - ["UDP", "514"]
      - ["TCP", "514"]
```

You can customize this file to add new exporters or modify existing ones.

### Custom Configuration File

You can specify a custom configuration file using the `PORT_CONFIG` environment variable:

```bash
export PORT_CONFIG=/path/to/your/custom_config.yaml
python app.py
```

## Installation

### Option 1: Using Docker (Recommended)

The easiest way to run this application is using Docker:

```bash
# Pull the latest image
docker pull brownster/portmapper:latest

# Run the container
docker run -p 5000:5000 brownster/portmapper:latest
```

To use a custom configuration with Docker, mount your config file:

```bash
docker run -p 5000:5000 -v /path/to/your/custom_config.yaml:/app/port_config.yaml brownster/portmapper:latest
```

Then access the application at http://localhost:5000

The Docker image includes all necessary dependencies for PDF generation, including wkhtmltopdf and its required libraries.

#### Building Docker Image Locally

If you want to build the Docker image locally:

```bash
# Clone the repository
git clone https://github.com/Brownster/portmapper.git
cd portmapper

# Build the Docker image
docker build -t portmapper .

# Run the container
docker run -p 5000:5000 portmapper
```

### Option 2: Manual Installation

To set up the project locally, follow these steps:

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Brownster/portmapper.git
   cd firewall-request-generator

    Set Up a Virtual Environment (optional but recommended):

    bash

python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

Install Dependencies

bash

pip install -r requirements.txt

This command installs all the necessary Python packages, including Flask.

Environment Variables

Set up the necessary environment variables, if any (e.g., FLASK_APP, FLASK_ENV for development).

bash

    export FLASK_APP=app.py
    export FLASK_ENV=development

Running the Application

To run the application locally:

bash

flask run

This will start the Flask server on http://127.0.0.1:5000/, where you can access the web interface to upload CSV files and generate firewall requests.
## Usage

1. **Access the Web Interface**: Open a web browser and go to http://127.0.0.1:5000/
2. **Upload a CSV File**: 
   - Click the "Browse" button to select a CSV file from your computer that matches the expected format
   - Enter the required MaaS-NG IP and FQDN
   - Submit the form
3. **Select Target Servers**:
   - The app displays a list of all servers found in the CSV
   - Servers identified as edge cases (with monitoring flags but no exporters) will be highlighted
   - For all servers, you can configure custom ports by clicking the "Configure Ports" button
   - Each exporter can have custom "To Target" and "From Target" ports configured
   - Blackbox monitoring features (SSH-banner, TCP-connect, SNMP, SSL) can also have custom ports
   - Use the checkboxes to select which servers to include in your firewall request
4. **Choose Output Format**:
   - Select your preferred output format (CSV, Excel, PDF, Firewall Check CSV, or firewall-specific formats)
   - Click "Generate Firewall Request"
5. **Download the Result**:
   - The file will be generated and downloaded automatically
   - For Firewall Check CSV, you can also download the firewall check script to test connectivity

## Docker Hub Integration

This project is configured to automatically build and push Docker images to Docker Hub using GitHub Actions. When you push to the main branch or create a tag, a new Docker image will be built and pushed to Docker Hub.

### Setting Up GitHub Actions for Your Fork

If you fork this project and want to use GitHub Actions to push to your own Docker Hub account:

1. Go to your GitHub repository settings
2. Navigate to Secrets and Variables > Actions
3. Add the following repository secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Your Docker Hub access token (create one in Docker Hub account settings)

4. Update the Docker image name in the GitHub Actions workflow file (`.github/workflows/docker-build-push.yml`) to use your Docker Hub username.

## Contributing

Contributions are welcome, and any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Tests

The application includes a comprehensive suite of tests to ensure the reliability and correctness of its functionality, with over 80% code coverage. These tests cover various aspects of the application, including:

- **CSV Upload**: Tests uploading a CSV file and checks for redirection and session variables.
- **Process Page**: Tests that the process page displays all hostnames from the CSV.
- **Edge Case Detection**: Tests that edge cases are properly detected and displayed with port input fields.
- **Edge Case Port Submission**: Tests submitting edge case port configurations directly in the process page.
- **Output Format Options**: Tests that different output formats are supported.
- **Firewall Check CSV Option**: Tests that the firewall check CSV option is available.
- **Download Check Script**: Tests downloading the firewall check script.
- **Firewall Format Generation**: Tests generation of firewall-specific formats.
- **Firewall Check CSV Generation**: Tests generation of the firewall check CSV format.
- **Port Mappings Tab**: Tests that the port mappings tab is present on the process page.
- **Port Mappings API**: Tests both GET and POST endpoints for fetching and setting port mappings.
- **Custom Port Mappings Integration**: Tests that custom port mappings are used in the CSV generation process.
- **Exporter-Specific Port Configurations**: Tests handling of custom port configurations for specific exporters.
- **Blackbox Monitoring Configurations**: Tests port customization for blackbox monitoring (SNMP, SSL, etc.).
- **Error Handling**: Tests various error scenarios such as missing files, invalid formats, etc.
- **Configuration Export**: Tests exporting the current configuration as YAML.
- **File Cleanup**: Tests the automatic cleanup of temporary files.

The CI/CD pipeline includes automatic code coverage measurement, ensuring that test coverage remains above the 70% threshold. A coverage badge is automatically generated and displayed at the top of this README.

### Test Coverage

The coverage badge shows the current test coverage percentage for the application. The badge color indicates the coverage level:
- Green: 80% or higher coverage (excellent)
- Yellow: 70-79% coverage (good)
- Red: Below 70% coverage (needs improvement)

The coverage is calculated using pytest-cov and is updated automatically with each push to the main branch.

### Running Tests

You can run the tests locally using pytest:

```bash
# Run all tests with coverage report
pytest test_app.py test_app_coverage.py --cov=app --cov-report=term

# Run a specific test
pytest test_app.py::test_process_page -v

# Run tests with output
pytest -v
```

License

Distributed under the MIT License. See LICENSE for more information.
