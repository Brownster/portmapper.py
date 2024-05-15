# Port Mapper - Firewall Request Generator

This Flask application automates the generation of firewall requests from uploaded CSV files. It parses specific network configurations from the CSV, matches them against a predefined set of exporter configurations, and outputs a new CSV with detailed firewall rules.

## Features

- **CSV Upload**: Users can upload CSV files containing details about network endpoints.
- **Rule Mapping**: Maps incoming and outgoing rules based on predefined configurations.
- **FQDN and IP Handling**: Handles both Fully Qualified Domain Names (FQDN) and IP addresses to specify sources and destinations.
- **Secure File Handling**: Temporarily stores uploaded files in a secure manner and cleans up old files regularly.
- **User Feedback**: Provides user feedback via flash messages for file upload success or failure.

Here is a breakdown of the required CSV file fields mentioned in your script:

    FQDN: Fully Qualified Domain Name of the target server. This field is crucial as it is used to match the target server in the firewall rule entries.
    IP Address: The IP address of the target server. Like the FQDN, it is used to specify the source or destination IP in firewall rules.
    Exporter_name_os: This field appears to indicate the operating system or platform specific exporter configurations, which determine what ports and protocols are allowed for source communications.
    Exporter_name_app: This field seems to represent the application-specific exporter configurations, detailing the ports and protocols used for destination communications.

These fields are utilized in the script to determine the rule mappings and to generate the necessary firewall configurations. When you create a CSV file for upload, each record should at least include these columns to ensure the script can process it correctly.
Example CSV Structure

Your CSV files should have a structure similar to the following:

csv

FQDN,IP Address,Exporter_name_os,Exporter_name_app
example1.domain.com,192.168.1.1,exporter_linux,exporter_iq
example2.domain.com,192.168.1.2,exporter_windows,exporter_aacc

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


## Prerequisites

Before you can run this application, you'll need the following installed:
- Python 3.6 or higher
- Flask
- Werkzeug (usually installed with Flask)

## Installation

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

Contributing

Contributions are welcome, and any contributions you make are greatly appreciated.

    Fork the Project
    Create your Feature Branch (git checkout -b feature/AmazingFeature)
    Commit your Changes (git commit -m 'Add some AmazingFeature')
    Push to the Branch (git push origin feature/AmazingFeature)
    Open a Pull Request

License

Distributed under the MIT License. See LICENSE for more information.
