# Port Mapper - Firewall Request Generator

This Flask application automates the generation of firewall requests from uploaded CSV files. It parses specific network configurations from the CSV, matches them against a predefined set of exporter configurations, and outputs a new CSV with detailed firewall rules.

## Features

- **CSV Upload**: Users can upload CSV files containing details about network endpoints.
- **Rule Mapping**: Maps incoming and outgoing rules based on predefined configurations.
- **FQDN and IP Handling**: Handles both Fully Qualified Domain Names (FQDN) and IP addresses to specify sources and destinations.
- **Secure File Handling**: Temporarily stores uploaded files in a secure manner and cleans up old files regularly.
- **User Feedback**: Provides user feedback via flash messages for file upload success or failure.

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

Example CSV structure:

```
FQDN,IP Address,Exporter_name_os,Exporter_name_app
```

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
Example Output CSV

Based on the input data and the provided exporter configurations, the output would list detailed firewall rules needed for each server. For simplicity, let's say the Monitoring Server IP is 10.10.10.10 and its FQDN is monitor.example.com.

The output might look like this:

Source_FQDN,Source_IP_Address,Destination_FQDN,Destination_IP_Address,Port
monitor.example.com,10.10.10.10,server1.example.com,192.168.1.10,"TCP: 22"
monitor.example.com,10.10.10.10,server1.example.com,192.168.1.10,"TCP: 443"
server1.example.com,192.168.1.10,monitor.example.com,10.10.10.10,"UDP: 514"
server1.example.com,192.168.1.10,monitor.example.com,10.10.10.10,"TCP: 514"
server2.example.com,192.168.1.11,monitor.example.com,10.10.10.10,"UDP: 514"
server2.example.com,192.168.1.11,monitor.example.com,10.10.10.10,"TCP: 514"
server3.example.com,192.168.1.12,monitor.example.com,10.10.10.10,"UDP: 162"
server3.example.com,192.168.1.12,monitor.example.com,10.10.10.10,"UDP: 514"
server3.example.com,192.168.1.12,monitor.example.com,10.10.10.10,"TCP: 514"



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

## Installation

### Option 1: Using Docker (Recommended)

The easiest way to run this application is using Docker:

```bash
# Pull the latest image
docker pull brownster/portmapper:latest

# Run the container
docker run -p 5000:5000 brownster/portmapper:latest
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
Usage

    Access the Web Interface: Open a web browser and go to http://127.0.0.1:5000/.
    Upload a CSV File: Click the "Browse" button to select a CSV file from your computer that matches the expected format.
    Submit the Form: After selecting the file, enter the required MaaS-NG IP and FQDN, then submit the form.
    Download the Resulting CSV: If the file is processed successfully, you will be prompted to download the resulting CSV with the firewall rules.

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

License

Distributed under the MIT License. See LICENSE for more information.
