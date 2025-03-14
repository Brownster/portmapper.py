"""
Flask application for processing CSV files and generating firewall port requests.
"""
import io
import csv
import os
import uuid
import time
import json
import logging
from datetime import datetime
from flask import Flask, request, redirect, url_for, flash, send_file, session, render_template, jsonify, make_response
from werkzeug.utils import secure_filename
import pandas as pd
import pdfkit  # For PDF generation (requires wkhtmltopdf installed)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '123456789')  # Better to set via environment variable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Directory to store uploaded files temporarily
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Create the upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Template CSV contents
TEMPLATE_CSV_CONTENT = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,Exporter_name_app_2,Exporter_name_app_3
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,
server2.example.com,192.168.1.11,exporter_windows,exporter_mpp,,
db1.example.com,192.168.1.20,exporter_linux,exporter_redis,,
"""

# Function to delete old temporary files
def cleanup_old_files(directory, max_age_in_seconds=3600):
    """Delete files older than max_age_in_seconds from the directory."""
    current_time = time.time()
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_in_seconds:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted old file: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting {file_path}: {e}")

# Your existing function create_port_csv with added logging and error handling
def create_port_csv(input_file, output_file, maas_ng_ip, maas_ng_fqdn, selected_hostnames=None):
    """Generate a CSV file with port mappings for the selected hostnames."""
    port_mappings = {
        "exporter_cms": {
            "src": [("TCP", "22"), ("ICMP", "ping"), ("TCP", "443"), ("SSL", "443")],
            "dst": [],
        },
        "exporter_aes": {
            "src": [("TCP", "22"), ("ICMP", "ping"), ("TCP", "443"), ("SSL", "8443")],
            "dst": [("UDP", "514"), ("TCP", "514"), ("UDP", "162")],
        },
        "exporter_aessnmp": {
            "src": [("TCP", "22"), ("UDP", "161"), ("TCP", "443"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_gateway": {
            "src": [("UDP", "161"), ("TCP", "22"), ("ICMP", "ping")],
            "dst": [("UDP", "162")],
        },
        "exporter_ams": {
            "src": [("TCP", "22"), ("UDP", "161"), ("TCP", "8443"), ("ICMP", "ping"), ("SSL", "8443")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_sm": {
            "src": [("TCP", "22"), ("ICMP", "ping")],
            "dst": [("UDP", "162")],
        },
        "exporter_avayasbc": {
            "src": [("TCP", "22"), ("TCP", "222"), ("UDP", "161"), ("TCP", "443"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_aaep": {
            "src": [("TCP", "22"), ("TCP", "5432"), ("UDP", "161"), ("TCP", "443"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_mpp": {
            "src": [("TCP", "22"), ("ICMP", "ping")],
            "dst": [],
        },
        "exporter_windows": {
            "src": [("TCP", "9182"), ("ICMP", "ping")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_linux": {
            "src": [("TCP", "22"), ("ICMP", "ping")],
            "dst": [],
        },
        "exporter_ipo": {
            "src": [("TCP", "22"), ("TCP", "443"), ("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_iq": {
            "src": [("TCP", "22"), ("TCP", "443"), ("ICMP", "ping")],
            "dst": [],
        },
        "exporter_weblm": {
            "src": [("TCP", "22"), ("TCP", "443"), ("TCP", "52233"), ("ICMP", "ping"), ("SSL", "443"), ("SSL", "52233")],
            "dst": [],
        },
        "exporter_aacc": {
            "src": [("TCP", "9182"), ("TCP", "8443"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_wfodb": {
            "src": [("TCP", "1433"), ("TCP", "9182"), ("ICMP", "ping")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_verint": {
            "src": [("TCP", "9182"), ("ICMP", "ping"), ("TCP", "8443"), ("ICMP", "ping"), ("SSL", "8443")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_network": {
            "src": [("UDP", "161"), ("ICMP", "ping")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_tcti": {
            "src": [("TCP", "8080"), ("ICMP", "ping")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_callback": {
            "src": [("TCP", "1433"), ("ICMP", "ping")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_nuancelm": {
            "src": [("TCP", "9182"), ("TCP", "27000"), ("ICMP", "ping")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_jmx": {
            "src": [("TCP", "7080"), ("ICMP", "ping")],
            "dst": [],
        },
        "exporter_breeze": {
            "src": [("TCP", "22"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_acm": {
            "src": [("TCP", "22"), ("TCP", "5022"), ("TCP", "443"), ("UDP", "161"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "514"), ("TCP", "514"), ("UDP", "162")],
        },
        "exporter_vmware": {
            "src": [("TCP", "22"), ("ICMP", "PING"), ("TCP", "443")],
            "dst": [],
        },
        "exporter_kafka": {
            "src": [("TCP", "9092")],
            "dst": [],
        },
        "exporter_drac": {
            "src": [("TCP", "22"), ("ICMP", "PING"), ("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_pfsense": {
            "src": [("TCP", "22"), ("ICMP", "PING"), ("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_aic": {
            "src": [("TCP", "9183"), ("ICMP", "ping"), ("SSL", "443")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_voiceportal": {
            "src": [("TCP", "5432"), ("ICMP", "ping"), ("TCP", "443"), ("TCP", "22")],
            "dst": [],
        },
        "exporter_aam": {
            "src": [("ICMP", "ping"), ("TCP", "8443"), ("TCP", "22"), ("UDP", "161"), ("SSL", "8443")],
            "dst": [("UDP", "514"), ("TCP", "514"), ("UDP", "162")],
        },
        "exporter_pc5": {
            "src": [("ICMP", "ping"), ("TCP", "22")],
            "dst": [],
        },
        "exporter_audiocodes": {
            "src": [("ICMP", "ping"), ("TCP", "22"), ("UDP", "161"), ("SSL", "443")],
            "dst": [("UDP", "514"), ("TCP", "514"), ("UDP", "162"), ("SSL", "443")],
        },
        "exporter_redis": {
            "src": [("TCP", "6379")],
            "dst": [],
        },
    }

    unique_entries = set()
    processed_count = 0
    skipped_count = 0

    try:
        reader = csv.DictReader(input_file)
        writer = csv.writer(output_file)
        writer.writerow([
            "Source_FQDN", "Source_IP_Address", "Destination_FQDN", 
            "Destination_IP_Address", "Proto", "Port", "Description"
        ])

        for row in reader:
            target_fqdn = row.get("FQDN", "")
            if not target_fqdn:
                logger.warning(f"Skipping row with missing FQDN: {row}")
                skipped_count += 1
                continue

            if selected_hostnames is not None and target_fqdn not in selected_hostnames:
                continue

            ip = row.get("IP Address", "")
            if not ip:
                logger.warning(f"Skipping row with missing IP Address for {target_fqdn}")
                skipped_count += 1
                continue

            # Collect all exporter names, filtering out None or empty values
            exporters = [
                row.get("Exporter_name_os", ""), 
                row.get("Exporter_name_app", ""), 
                row.get("Exporter_name_app_2", ""), 
                row.get("Exporter_name_app_3", "")
            ]
            exporters = [exporter for exporter in exporters if exporter]

            if not exporters:
                logger.warning(f"No exporters found for {target_fqdn}")
                skipped_count += 1
                continue

            for exporter in exporters:
                if exporter in port_mappings:
                    for protocol, port in port_mappings[exporter]["src"]:
                        description = f"Monitoring from {maas_ng_fqdn} to {target_fqdn} ({exporter})"
                        entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, protocol, port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1

                    for protocol, port in port_mappings[exporter]["dst"]:
                        description = f"Return traffic from {target_fqdn} to {maas_ng_fqdn} ({exporter})"
                        entry = (target_fqdn, ip, maas_ng_fqdn, maas_ng_ip, protocol, port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1
                else:
                    logger.warning(f"Unknown exporter type: {exporter} for {target_fqdn}")

        logger.info(f"Processed {processed_count} port mappings, skipped {skipped_count} items")
        return processed_count, skipped_count
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        raise

@app.route("/", methods=["GET", "POST"])
def upload_csv():
    """Handle file uploads and redirect to the processing page."""
    if request.method == "POST":
        try:
            if "file" not in request.files:
                flash("No file selected", "error")
                return redirect(request.url)

            maas_ng_fqdn = request.form.get("maas_ng_fqdn")
            if not maas_ng_fqdn:
                flash("MaaS-NG FQDN is required", "error")
                return redirect(request.url)

            maas_ng_ip = request.form.get("maas_ng_ip")
            if not maas_ng_ip:
                flash("MaaS-NG IP address is required", "error")
                return redirect(request.url)

            file = request.files["file"]
            if file.filename == "":
                flash("No file selected", "error")
                return redirect(request.url)

            if file and file.filename.endswith('.csv'):
                # Generate a unique filename
                filename = secure_filename(str(uuid.uuid4()) + '.csv')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                logger.info(f"Saved uploaded file to {file_path}")

                # Save to session
                session['file_path'] = file_path
                session['maas_ng_fqdn'] = maas_ng_fqdn
                session['maas_ng_ip'] = maas_ng_ip
                session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                return redirect(url_for("process"))
            else:
                flash("Please upload a CSV file", "error")
                return redirect(request.url)
        except Exception as e:
            logger.error(f"Error in upload_
