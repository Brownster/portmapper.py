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
import shutil  # For checking executable paths
from port_defaults import DEFAULT_PORT_SUGGESTIONS, COMMON_APPLICATION_PORTS, PORT_TEMPLATES, FIREWALL_TEMPLATES

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
TEMPLATE_CSV_CONTENT = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,Exporter_name_app_2,Exporter_name_app_3,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,,, 
server2.example.com,192.168.1.11,exporter_windows,exporter_mpp,,,,,,,
db1.example.com,192.168.1.20,exporter_linux,exporter_redis,,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,,,8080,,true
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
    """Generate a CSV file with port mappings for the selected hostnames.
    
    This function processes the CSV file and generates port mappings for servers with 
    standard exporters. Servers without exporters but with special monitoring flags
    are handled separately through the edge case flow.
    """
    # Define the default port mappings
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
    
    # Check for custom port mappings in session and merge them with the defaults
    if 'custom_port_mappings' in session and session['custom_port_mappings']:
        custom_mappings = session['custom_port_mappings']
        logger.info(f"Found {len(custom_mappings)} custom port mappings in session")
        
        # Add custom mappings to the port_mappings dictionary
        for exporter_name, mapping in custom_mappings.items():
            # Convert the format from the client-side format to the server-side format
            if 'src' in mapping and isinstance(mapping['src'], list):
                src_ports = [tuple(port_entry) for port_entry in mapping['src']]
            else:
                src_ports = []
                
            if 'dst' in mapping and isinstance(mapping['dst'], list):
                dst_ports = [tuple(port_entry) for port_entry in mapping['dst']]
            else:
                dst_ports = []
                
            port_mappings[exporter_name] = {
                "src": src_ports,
                "dst": dst_ports
            }

    unique_entries = set()
    processed_count = 0
    skipped_count = 0

    try:
        # Detect the header row by looking for 'FQDN' within the first 10 rows
        header_row = None
        all_rows = list(csv.reader(input_file))
        
        if not all_rows:
            logger.error("Empty CSV file provided")
            raise ValueError("The provided CSV file is empty")
            
        # Look for the header row containing 'FQDN'
        for i, row in enumerate(all_rows[:min(10, len(all_rows))]):
            if any('FQDN' in str(cell).upper() for cell in row):
                header_row = i
                logger.info(f"Found header row at line {header_row + 1}")
                break
        
        if header_row is None:
            logger.error("Could not find a header row with 'FQDN' in the first 10 rows")
            raise ValueError("Could not find FQDN column in the CSV file. Please check your file format.")
        
        # Prepare the data rows (skip header rows)
        data_rows = all_rows[header_row + 1:]
        
        # Get the header row and create a CSV reader for the data
        headers = all_rows[header_row]
        
        # Find the index of FQDN and IP Address columns
        fqdn_index = None
        ip_index = None
        
        for i, header in enumerate(headers):
            if 'FQDN' in str(header).upper():
                fqdn_index = i
            if 'IP' in str(header).upper() and 'ADDRESS' in str(header).upper():
                ip_index = i
        
        if fqdn_index is None or ip_index is None:
            logger.error("Could not find required columns (FQDN and IP Address)")
            raise ValueError("Could not find required columns. Please check your CSV format.")
        
        # Set up the output CSV
        writer = csv.writer(output_file)
        writer.writerow([
            "Source_FQDN", "Source_IP_Address", "Destination_FQDN", 
            "Destination_IP_Address", "Proto", "Port", "Description"
        ])
        
        # Process the data rows
        for row in data_rows:
            if len(row) <= max(fqdn_index, ip_index):
                # Skip rows that don't have enough columns
                continue
                
            # Get FQDN and IP
            target_fqdn = row[fqdn_index].strip()
            ip = row[ip_index].strip()
            
            if not target_fqdn:
                logger.warning(f"Skipping row with missing FQDN")
                skipped_count += 1
                continue

            if selected_hostnames is not None and target_fqdn not in selected_hostnames:
                continue

            if not ip:
                logger.warning(f"Skipping row with missing IP Address for {target_fqdn}")
                skipped_count += 1
                continue

            # Collect all exporter names by looking for columns with "Exporter" in the name
            exporters = []
            for i, header in enumerate(headers):
                if i >= len(row):
                    continue
                if 'EXPORTER' in str(header).upper() and row[i].strip():
                    exporters.append(row[i].strip())

            if not exporters:
                logger.warning(f"No exporters found for {target_fqdn}")
                skipped_count += 1
                continue

            for exporter in exporters:
                # Convert to lowercase for case-insensitive comparison
                exporter_lower = exporter.lower()
                exporter_key = None
                
                # Find matching exporter in the port mappings
                for key in port_mappings:
                    if key.lower() == exporter_lower:
                        exporter_key = key
                        break
                
                if exporter_key:
                    # Use the matched key to get port mappings
                    for protocol, port in port_mappings[exporter_key]["src"]:
                        description = f"Monitoring from {maas_ng_fqdn} to {target_fqdn} ({exporter})"
                        entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, protocol, port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1

                    for protocol, port in port_mappings[exporter_key]["dst"]:
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
            logger.error(f"Error in upload_csv: {e}")
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(request.url)
    
    # Run cleanup in each request
    try:
        cleanup_old_files(app.config['UPLOAD_FOLDER'])
    except Exception as e:
        logger.error(f"Error cleaning up temporary files: {e}")
    
    return render_template("index.html")

@app.route("/process", methods=["GET", "POST"])
def process():
    """Process the uploaded CSV file and display the hostnames for selection."""
    # Check if we have a file path in the session
    if 'file_path' not in session:
        flash("Please upload a CSV file first", "error")
        return redirect(url_for("upload_csv"))
    
    file_path = session['file_path']
    maas_ng_fqdn = session.get('maas_ng_fqdn', '')
    maas_ng_ip = session.get('maas_ng_ip', '')
    
    try:
        # Read the CSV file and extract hostnames with flexible header detection
        hostnames = []
        hostnames_info = []
        
        with open(file_path, 'r') as f:
            # Read the entire CSV content
            all_rows = list(csv.reader(f))
            
            if not all_rows:
                flash("Empty CSV file provided", "error")
                return redirect(url_for("upload_csv"))
            
            # Look for the header row containing 'FQDN' within the first 10 rows
            header_row = None
            for i, row in enumerate(all_rows[:min(10, len(all_rows))]):
                if any('FQDN' in str(cell).upper() for cell in row):
                    header_row = i
                    logger.info(f"Found header row at line {header_row + 1}")
                    break
            
            if header_row is None:
                flash("Could not find FQDN column in the CSV file. Please check your file format.", "error")
                return redirect(url_for("upload_csv"))
            
            # Get headers and data rows
            headers = all_rows[header_row]
            data_rows = all_rows[header_row + 1:]
            
            # Find the index of the FQDN and IP Address columns
            fqdn_index = None
            ip_index = None
            
            # Find indices of the edge case columns (SSH-banner, TCP-connect, etc.)
            ssh_banner_index = None
            tcp_connect_index = None
            tcp_port_index = None
            snmp_index = None
            ssl_index = None
            exporter_indices = []
            
            for i, header in enumerate(headers):
                header_upper = str(header).upper()
                if 'FQDN' in header_upper:
                    fqdn_index = i
                elif 'IP' in header_upper and 'ADDRESS' in header_upper:
                    ip_index = i
                elif 'SSH-BANNER' in header_upper.replace('_', '-'):
                    ssh_banner_index = i
                elif 'TCP-CONNECT' in header_upper.replace('_', '-') and 'PORT' not in header_upper:
                    tcp_connect_index = i
                elif 'TCP' in header_upper and 'CONNECT' in header_upper and 'PORT' in header_upper:
                    tcp_port_index = i
                elif 'SNMP' in header_upper:
                    snmp_index = i
                elif 'SSL' in header_upper or 'EXPORTER_SSL' in header_upper:
                    ssl_index = i
                elif 'EXPORTER' in header_upper:
                    exporter_indices.append(i)
            
            if fqdn_index is None or ip_index is None:
                flash("Could not find required columns (FQDN and IP Address) in the CSV file", "error")
                return redirect(url_for("upload_csv"))
            
            # Save column indices in session for later use
            session['csv_columns'] = {
                'fqdn': fqdn_index,
                'ip': ip_index,
                'ssh_banner': ssh_banner_index,
                'tcp_connect': tcp_connect_index,
                'tcp_port': tcp_port_index,
                'snmp': snmp_index,
                'ssl': ssl_index,
                'exporters': exporter_indices
            }
            
            # Process the data rows
            for row in data_rows:
                if len(row) <= max(fqdn_index, ip_index):  # Skip rows that don't have enough columns
                    continue
                    
                fqdn = row[fqdn_index].strip()
                ip = row[ip_index].strip()
                
                if not fqdn or not ip:  # Skip rows with missing FQDN or IP
                    continue
                
                # Identify if this is an edge case (has monitoring flags but no exporters)
                is_edge_case = False
                has_exporters = False
                monitoring_flags = {
                    'ssh_banner': False,
                    'tcp_connect': False,
                    'tcp_port': None,
                    'snmp': False,
                    'ssl': False
                }
                
                # Check for exporters
                for idx in exporter_indices:
                    if idx < len(row) and row[idx].strip():
                        has_exporters = True
                        break
                
                # If it has exporters, it's not an edge case
                if not has_exporters:
                    # Check SSH Banner
                    if ssh_banner_index is not None and ssh_banner_index < len(row):
                        value = row[ssh_banner_index].strip().lower()
                        if value in ('1', 'true', 'yes', 'y', 't'):
                            monitoring_flags['ssh_banner'] = True
                            is_edge_case = True
                
                    # Check TCP Connect
                    if tcp_connect_index is not None and tcp_connect_index < len(row):
                        value = row[tcp_connect_index].strip().lower()
                        if value in ('1', 'true', 'yes', 'y', 't'):
                            monitoring_flags['tcp_connect'] = True
                            is_edge_case = True
                
                    # Check TCP Port
                    if tcp_port_index is not None and tcp_port_index < len(row):
                        value = row[tcp_port_index].strip()
                        if value and value not in ('0', 'false', 'no', 'n', ''):
                            monitoring_flags['tcp_port'] = value
                            is_edge_case = True
                
                    # Check SNMP
                    if snmp_index is not None and snmp_index < len(row):
                        value = row[snmp_index].strip().lower()
                        if value in ('1', 'true', 'yes', 'y', 't'):
                            monitoring_flags['snmp'] = True
                            is_edge_case = True
                
                    # Check SSL
                    if ssl_index is not None and ssl_index < len(row):
                        value = row[ssl_index].strip().lower()
                        if value in ('1', 'true', 'yes', 'y', 't'):
                            monitoring_flags['ssl'] = True
                            is_edge_case = True
                
                # Create suggested to_target and from_target ports
                to_target_ports = []
                from_target_ports = []
                
                if monitoring_flags['ssh_banner']:
                    to_target_ports.append('22')
                
                if monitoring_flags['tcp_connect']:
                    to_target_ports.append('3389')
                
                if monitoring_flags['tcp_port']:
                    to_target_ports.append(monitoring_flags['tcp_port'])
                
                if monitoring_flags['ssl']:
                    to_target_ports.append('443')
                
                if monitoring_flags['snmp']:
                    to_target_ports.append('161')
                    from_target_ports.append('162')
                
                # Add host to the list
                hostnames.append(fqdn)
                host_info = {
                    'fqdn': fqdn,
                    'ip': ip,
                    'is_edge_case': is_edge_case
                }
                
                # Add monitoring flags and suggested ports if this is an edge case
                if is_edge_case:
                    host_info.update({
                        'monitoring_flags': monitoring_flags,
                        'suggested_to_target': ','.join(to_target_ports),
                        'suggested_from_target': ','.join(from_target_ports)
                    })
                
                hostnames_info.append(host_info)
        
        if not hostnames:
            flash("No valid hostnames found in the uploaded CSV", "error")
            return redirect(url_for("upload_csv"))
        
        return render_template(
            "process.html", 
            hostnames=hostnames, 
            hostnames_info=hostnames_info, 
            maas_ng_fqdn=maas_ng_fqdn, 
            maas_ng_ip=maas_ng_ip
        )
        
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")
        flash(f"Error processing the uploaded file: {str(e)}", "error")
        return redirect(url_for("upload_csv"))

@app.route("/generate_output_csv", methods=["POST"])
def generate_output_csv():
    """Generate the output CSV file based on the selected hostnames."""
    try:
        # Get form data
        selected_hostnames = request.form.getlist('selected_hostnames')
        maas_ng_fqdn = request.form.get('maas_ng_fqdn')
        maas_ng_ip = request.form.get('maas_ng_ip')
        output_format = request.form.get('output_format', 'csv')
        
        logger.info(f"Generate request: format={output_format}, hosts={len(selected_hostnames)}")
        
        if not selected_hostnames:
            flash("Please select at least one hostname", "error")
            return redirect(url_for("process"))
        
        if not maas_ng_fqdn or not maas_ng_ip:
            flash("Missing MaaS-NG information", "error")
            return redirect(url_for("upload_csv"))
        
        # Get the file path from session
        input_file_path = session.get('file_path')
        if not input_file_path:
            flash("Please upload a CSV file first", "error")
            return redirect(url_for("upload_csv"))
        
        # Process edge case port inputs directly from form
        edge_case_configs = {}
        
        # Collect edge case configurations from the form
        for hostname in selected_hostnames:
            to_target_key = f"to_target_{hostname}"
            from_target_key = f"from_target_{hostname}"
            
            # Check if this hostname has port configurations in the form
            if to_target_key in request.form or from_target_key in request.form:
                # Get the data-ip hidden field directly
                ip_data_key = f"data-ip-{hostname}"
                ip = request.form.get(ip_data_key)
                
                # If that didn't work, try other methods
                if not ip:
                    # Try to get the IP from the data-ip attribute of the checkbox
                    for checkbox in request.form.getlist('selected_hostnames'):
                        if checkbox == hostname:
                            # Try to get the data-ip attribute from the checkbox
                            ip_attr = request.form.get(f"selected_hostnames[data-ip]")
                            if ip_attr:
                                ip = ip_attr
                                break
                
                # If we still don't have the IP, look in the session
                if not ip:
                    # Try the CSV columns data in session
                    columns = session.get('csv_columns', {})
                    if columns and 'fqdn' in columns and 'ip' in columns:
                        # Open the CSV and search for the hostname
                        with open(input_file_path, 'r') as f:
                            csv_reader = csv.reader(f)
                            rows = list(csv_reader)
                            
                            # Check header row location
                            header_row = None
                            for i, row in enumerate(rows[:10]):  # Check first 10 rows
                                if any('FQDN' in str(cell).upper() for cell in row):
                                    header_row = i
                                    break
                            
                            if header_row is not None:
                                # Get column indices
                                headers = rows[header_row]
                                fqdn_idx = None
                                ip_idx = None
                                
                                for i, header in enumerate(headers):
                                    if 'FQDN' in str(header).upper():
                                        fqdn_idx = i
                                    elif 'IP' in str(header).upper() and 'ADDRESS' in str(header).upper():
                                        ip_idx = i
                                
                                if fqdn_idx is not None and ip_idx is not None:
                                    # Search for the hostname in the data rows
                                    for row in rows[header_row + 1:]:
                                        if len(row) > max(fqdn_idx, ip_idx) and row[fqdn_idx].strip() == hostname:
                                            ip = row[ip_idx].strip()
                                            break
                
                # If we found an IP and have at least one port, add to edge case configs
                if ip and (request.form.get(to_target_key, '').strip() or request.form.get(from_target_key, '').strip()):
                    edge_case_configs[hostname] = {
                        'ip': ip,
                        'to_target': request.form.get(to_target_key, '').strip(),
                        'from_target': request.form.get(from_target_key, '').strip()
                    }
                    logger.info(f"Added edge case config for {hostname} with IP {ip}")
        
        # Store edge case configs in session
        if edge_case_configs:
            session['edge_case_configs'] = edge_case_configs
            logger.info(f"Processed {len(edge_case_configs)} edge case configurations directly from form")
        
        # Continue with output generation
        return process_and_generate_output(selected_hostnames, maas_ng_fqdn, maas_ng_ip, output_format)
            
    except Exception as e:
        logger.error(f"Error in generate_output_csv: {e}")
        flash(f"Error generating output file: {str(e)}", "error")
        return redirect(url_for("process"))


def find_edge_cases(input_file_path, selected_hostnames):
    """
    This function is now kept as a reference but no longer used in the main flow.
    Edge cases are now identified directly in the process() function.
    """
    # Return an empty list as this function is no longer used in the main workflow
    return []




def process_and_generate_output(selected_hostnames, maas_ng_fqdn, maas_ng_ip, output_format):
    """Process CSV and generate output file with optional edge cases."""
    try:
        # Get the file path from session
        input_file_path = session.get('file_path')
        if not input_file_path:
            flash("Please upload a CSV file first", "error")
            return redirect(url_for("upload_csv"))
        
        # Generate a unique filename for the output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_basename = f"firewall_request_{timestamp}"
        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.csv")
        
        # Process the CSV file
        logger.info(f"Processing CSV file: {input_file_path}")
        with open(input_file_path, 'r') as input_file, open(output_file_path, 'w', newline='') as output_file:
            processed_count, skipped_count = create_port_csv(
                input_file,
                output_file,
                maas_ng_ip,
                maas_ng_fqdn,
                selected_hostnames
            )
            
            # Add edge case entries if any
            edge_case_configs = session.get('edge_case_configs', {})
            if edge_case_configs:
                # Close and reopen the file in append mode to add edge cases
                output_file.close()
                with open(output_file_path, 'a', newline='') as output_file:
                    writer = csv.writer(output_file)
                    edge_case_count = 0
                    
                    for fqdn, config in edge_case_configs.items():
                        ip = config['ip']
                        
                        # Process "to target" ports (monitoring server to target)
                        if config['to_target']:
                            ports = [p.strip() for p in config['to_target'].split(',') if p.strip()]
                            for port in ports:
                                description = f"Monitoring from {maas_ng_fqdn} to {fqdn} (edge case)"
                                writer.writerow([
                                    maas_ng_fqdn, maas_ng_ip, fqdn, ip, "TCP", port, description
                                ])
                                edge_case_count += 1
                        
                        # Process "from target" ports (target to monitoring server)
                        if config['from_target']:
                            ports = [p.strip() for p in config['from_target'].split(',') if p.strip()]
                            for port in ports:
                                description = f"Return traffic from {fqdn} to {maas_ng_fqdn} (edge case)"
                                writer.writerow([
                                    fqdn, ip, maas_ng_fqdn, maas_ng_ip, "TCP", port, description
                                ])
                                edge_case_count += 1
                    
                    logger.info(f"Added {edge_case_count} edge case entries")
                    processed_count += edge_case_count
        
        logger.info(f"CSV processing complete: processed={processed_count}, skipped={skipped_count}")
        
        # Create a dataframe from the CSV for all formats
        df = pd.read_csv(output_file_path)
        
        # Generate firewall check CSV if requested
        if output_format == 'check_csv':
            return generate_firewall_check_csv(
                df,
                timestamp,
                maas_ng_fqdn,
                maas_ng_ip,
                output_basename
            )
        
        # Check for firewall-specific formats
        if output_format in FIREWALL_TEMPLATES:
            return generate_firewall_script(
                df, 
                output_format, 
                timestamp, 
                maas_ng_fqdn, 
                maas_ng_ip, 
                selected_hostnames, 
                output_basename
            )
            
        # Handle standard output formats
        if output_format == 'excel':
            logger.info("Generating Excel file")
            excel_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.xlsx")
            df.to_excel(excel_file_path, index=False)
            
            logger.info(f"Sending Excel file: {excel_file_path}")
            return send_file(
                excel_file_path,
                as_attachment=True,
                download_name=f"firewall_request_{timestamp}.xlsx"
            )
            
        elif output_format == 'pdf':
            logger.info("Generating PDF file")
            pdf_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.pdf")
            
            # Format protocol column with color-coded styling
            def format_protocol(protocol):
                protocol_lower = str(protocol).lower()
                css_class = protocol_lower
                if "icmp" in protocol_lower:
                    css_class = "icmp"
                elif "tcp" in protocol_lower:
                    css_class = "tcp"
                elif "udp" in protocol_lower:
                    css_class = "udp"
                elif "ssl" in protocol_lower:
                    css_class = "ssl"
                return f'<span class="protocol {css_class}">{protocol}</span>'
                
            if 'Proto' in df.columns:
                df['Proto'] = df['Proto'].apply(format_protocol)
                
            # Get summary statistics
            device_count = len(selected_hostnames)
            port_mapping_count = len(df)
            
            # Generate HTML
            tables = [df.to_html(classes='data', index=False, escape=False)]
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            rendered = render_template(
                'pdf_template.html',
                tables=tables,
                now=now,
                maas_ng_fqdn=maas_ng_fqdn,
                maas_ng_ip=maas_ng_ip,
                device_count=device_count,
                port_mapping_count=port_mapping_count
            )
            
            # Try to find wkhtmltopdf
            wrapper_path = '/usr/local/bin/wkhtmltopdf.sh'
            if os.path.exists(wrapper_path) and os.access(wrapper_path, os.X_OK):
                logger.info("Using Docker wkhtmltopdf wrapper script")
                wkhtmltopdf_path = wrapper_path
            else:
                wkhtmltopdf_path = shutil.which('wkhtmltopdf')
            
            if not wkhtmltopdf_path:
                logger.error("wkhtmltopdf not found, falling back to CSV")
                flash("PDF generation requires wkhtmltopdf. Falling back to CSV format.", "error")
            else:
                # Generate PDF
                try:
                    config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
                    options = {
                        'page-size': 'A4',
                        'encoding': 'UTF-8',
                        'enable-local-file-access': None
                    }
                    
                    pdfkit.from_string(rendered, pdf_file_path, options=options, configuration=config)
                    
                    logger.info(f"Sending PDF file: {pdf_file_path}")
                    return send_file(
                        pdf_file_path,
                        as_attachment=True,
                        download_name=f"firewall_request_{timestamp}.pdf"
                    )
                except Exception as e:
                    logger.error(f"PDF generation failed: {e}")
                    flash(f"PDF generation failed: {str(e)}. Falling back to CSV format.", "error")
        
        # Default to CSV format
        logger.info(f"Sending CSV file: {output_file_path}")
        return send_file(
            output_file_path,
            as_attachment=True,
            download_name=f"firewall_request_{timestamp}.csv"
        )
        
    except Exception as e:
        logger.error(f"Error generating output: {e}")
        flash(f"Error generating output file: {str(e)}", "error")
        return redirect(url_for("process"))
        
def generate_firewall_check_csv(df, timestamp, maas_ng_fqdn, maas_ng_ip, output_basename):
    """Generate a CSV file containing only the monitoring server to target entries for firewall testing."""
    try:
        # Create a new filename for the firewall check CSV
        check_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}_check.csv")
        
        # Filter the dataframe to include only entries from monitoring server to targets
        check_df = df[df['Source_FQDN'] == maas_ng_fqdn].copy()
        
        # Keep only the columns needed for firewall checking
        check_columns = ['Destination_FQDN', 'Destination_IP_Address', 'Proto', 'Port']
        
        # Rename columns to make them more intuitive for shell script usage
        column_mapping = {
            'Destination_FQDN': 'Target_FQDN',
            'Destination_IP_Address': 'Target_IP',
            'Proto': 'Protocol',
            'Port': 'Port'
        }
        
        # Select and rename columns
        final_df = check_df[check_columns].rename(columns=column_mapping)
        
        # Sort by hostname and port for readability
        final_df = final_df.sort_values(['Target_FQDN', 'Port'])
        
        # Add a "Status" column that can be filled in by the shell script
        final_df['Status'] = ''
        
        # Save to CSV
        final_df.to_csv(check_file_path, index=False)
        
        logger.info(f"Generated firewall check CSV with {len(final_df)} entries")
        
        # Return the file to the user
        return send_file(
            check_file_path,
            as_attachment=True,
            download_name=f"firewall_check_{timestamp}.csv"
        )
        
    except Exception as e:
        logger.error(f"Error generating firewall check CSV: {e}")
        flash(f"Error generating firewall check CSV: {str(e)}. Falling back to standard CSV format.", "error")
        # Return the original CSV as a fallback
        original_csv = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.csv")
        return send_file(
            original_csv,
            as_attachment=True,
            download_name=f"firewall_request_{timestamp}.csv"
        )


def generate_firewall_script(df, format_type, timestamp, maas_ng_fqdn, maas_ng_ip, selected_hostnames, output_basename):
    """Generate firewall-specific configuration scripts."""
    try:
        template = FIREWALL_TEMPLATES.get(format_type)
        if not template:
            logger.error(f"Unknown firewall format: {format_type}")
            flash(f"Unknown firewall format: {format_type}. Falling back to CSV format.", "error")
            return process_and_generate_output(selected_hostnames, maas_ng_fqdn, maas_ng_ip, 'csv')
        
        # Create a new output file for the firewall config
        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.{format_type}")
        
        with open(output_file_path, 'w') as fw_file:
            # Add header
            fw_file.write(template['header'].format(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                maas_ng_fqdn=maas_ng_fqdn,
                maas_ng_ip=maas_ng_ip
            ))
            
            # Process rules according to specific format types
            if format_type == 'cisco':
                # Cisco ASA format
                for idx, row in df.iterrows():
                    if 'icmp' in row['Proto'].lower():
                        protocol = 'icmp'
                        port_spec = ''  # ICMP doesn't use ports in Cisco ASA
                    else:
                        protocol = row['Proto'].lower()
                        port_spec = f"eq {row['Port']}"
                        
                    fw_file.write(template['rule_format'].format(
                        protocol=protocol,
                        src_ip=row['Source_IP_Address'],
                        dst_ip=row['Destination_IP_Address'],
                        port_spec=port_spec,
                        description=row['Description']
                    ) + "\n")
                    
            elif format_type == 'juniper':
                # Juniper SRX format - first define applications
                app_definitions = set()
                for idx, row in df.iterrows():
                    app_def = template['rule_format'].format(
                        protocol=row['Proto'],
                        protocol_lower=row['Proto'].lower(),
                        port=row['Port']
                    )
                    app_definitions.add(app_def)
                
                # Write application definitions
                for app_def in sorted(app_definitions):
                    fw_file.write(app_def + "\n")
                fw_file.write("}\n")
                
                # Then write policies
                for idx, row in df.iterrows():
                    fw_file.write(template['policy_format'].format(
                        rule_id=idx + 1,
                        src_ip=row['Source_IP_Address'],
                        dst_ip=row['Destination_IP_Address'],
                        protocol=row['Proto'],
                        protocol_lower=row['Proto'].lower(),
                        port=row['Port']
                    ))
                
            elif format_type == 'paloalto':
                # Palo Alto format
                for idx, row in df.iterrows():
                    fw_file.write(template['rule_format'].format(
                        rule_id=idx + 1,
                        src_ip=row['Source_IP_Address'],
                        dst_ip=row['Destination_IP_Address'],
                        protocol=row['Proto'],
                        port=row['Port'],
                        description=row['Description']
                    ) + "\n")
                    
            elif format_type == 'iptables':
                # Linux iptables format
                for idx, row in df.iterrows():
                    protocol = "icmp" if 'icmp' in row['Proto'].lower() else row['Proto'].lower()
                    fw_file.write(template['rule_format'].format(
                        protocol_lower=protocol,
                        src_ip=row['Source_IP_Address'],
                        dst_ip=row['Destination_IP_Address'],
                        port=row['Port'],
                        description=row['Description']
                    ) + "\n")
            
            # Add footer with count
            fw_file.write(template['footer'].format(
                rule_count=len(df)
            ))
        
        # Send the file to user
        extension = "txt" if format_type == "iptables" else format_type
        logger.info(f"Sending {format_type} configuration file: {output_file_path}")
        return send_file(
            output_file_path,
            as_attachment=True,
            download_name=f"firewall_request_{timestamp}.{extension}"
        )
        
    except Exception as e:
        logger.error(f"Error generating firewall script: {e}")
        flash(f"Error generating firewall configuration: {str(e)}. Falling back to CSV format.", "error")
        return process_and_generate_output(selected_hostnames, maas_ng_fqdn, maas_ng_ip, 'csv')

@app.route("/download_template")
def download_template():
    """Provide a template CSV file for download."""
    try:
        template_file = io.StringIO(TEMPLATE_CSV_CONTENT)
        return send_file(
            io.BytesIO(template_file.getvalue().encode()),
            as_attachment=True,
            download_name="firewall_request_template.csv",
            mimetype="text/csv"
        )
    except Exception as e:
        logger.error(f"Error providing template: {e}")
        flash(f"Error downloading template: {str(e)}", "error")
        return redirect(url_for("upload_csv"))

@app.route("/download_check_script")
def download_check_script():
    """Provide the firewall check script for download."""
    try:
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_check.sh")
        
        # Check if the script exists
        if not os.path.exists(script_path):
            logger.error(f"Firewall check script not found at {script_path}")
            flash("The firewall check script could not be found on the server.", "error")
            return redirect(url_for("upload_csv"))
        
        return send_file(
            script_path,
            as_attachment=True,
            download_name="firewall_check.sh",
            mimetype="text/x-sh"
        )
    except Exception as e:
        logger.error(f"Error providing check script: {e}")
        flash(f"Error downloading firewall check script: {str(e)}", "error")
        return redirect(url_for("upload_csv"))

@app.route("/api/port_mappings", methods=["GET", "POST"])
def port_mappings_api():
    """API endpoint for getting and setting custom port mappings."""
    # Define the default port mappings (same as in create_port_csv function)
    default_port_mappings = {
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
        }
    }
    
    if request.method == "GET":
        # Return the built-in port mappings as JSON
        return jsonify(default_port_mappings)
    elif request.method == "POST":
        try:
            # Get custom port mappings from request
            custom_mappings = request.json
            
            # Store in session for use during CSV generation
            session['custom_port_mappings'] = custom_mappings
            
            logger.info(f"Received {len(custom_mappings)} custom port mappings")
            return jsonify({"status": "success", "message": f"Saved {len(custom_mappings)} custom port mappings"})
        except Exception as e:
            logger.error(f"Error saving custom port mappings: {e}")
            return jsonify({"status": "error", "message": str(e)}), 400
    
    # Default response for methods other than GET or POST
    return jsonify({"status": "error", "message": "Method not allowed"}), 405

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')