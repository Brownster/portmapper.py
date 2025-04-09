"""
Flask application for processing CSV files and generating firewall port requests.
"""
import io
import csv
import os
import uuid
import time
import json
import yaml
import logging
from datetime import datetime
from flask import Flask, request, redirect, url_for, flash, send_file, session, render_template, jsonify, make_response
from werkzeug.utils import secure_filename
import pandas as pd
import pdfkit  # For PDF generation (requires wkhtmltopdf installed)
import shutil  # For checking executable paths
from port_defaults import DEFAULT_PORT_SUGGESTIONS, COMMON_APPLICATION_PORTS, PORT_TEMPLATES, FIREWALL_TEMPLATES
from config_loader import load_config, get_port_mappings, get_column_mappings, get_columns_for_exporter

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

# Load configuration
try:
    config_path = os.environ.get('PORT_CONFIG', None)
    app_config = load_config(config_path)
    PORT_MAPPINGS = get_port_mappings(app_config)
    COLUMN_MAPPINGS = get_column_mappings(app_config)
    
    # Store config info for status page
    APP_CONFIG_INFO = {
        'loaded': True,
        'port_mappings_count': len(PORT_MAPPINGS),
        'column_mappings_count': len(COLUMN_MAPPINGS),
        'exporters': list(sorted(PORT_MAPPINGS.keys())),
    }
except Exception as e:
    error_message = f"Error loading configuration: {e}"
    print(error_message)
    logger.error(error_message)
    # Set empty defaults if config loading fails
    PORT_MAPPINGS = {}
    COLUMN_MAPPINGS = {}
    APP_CONFIG_INFO = {
        'loaded': False,
        'error': str(e),
        'port_mappings_count': 0,
        'column_mappings_count': 0,
        'exporters': []
    }

# Directory to store uploaded files temporarily
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

# Create the upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Template CSV contents - First row has column headers
TEMPLATE_CSV_CONTENT = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,Exporter_name_app_2,Exporter_name_app_3,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,,, 
server2.example.com,192.168.1.11,exporter_windows,exporter_mpp,,,,,,,
db1.example.com,192.168.1.20,exporter_linux,exporter_redis,,,,,,,
blackbox1.example.com,192.168.1.30,,,,TRUE,TRUE,,TRUE,TRUE
blackbox2.example.com,192.168.1.31,,,,,TRUE,8080,,TRUE
blackbox3.example.com,192.168.1.32,,,,TRUE,,,,,
blackbox4.example.com,192.168.1.33,,,,,,,,TRUE,
blackbox5.example.com,192.168.1.34,,,,,,,,,TRUE
blackbox6.example.com,192.168.1.35,,,,True,true,,true,TRUE
blackbox7.example.com,192.168.1.36,,,,1,yes,,1,yes
hybrid1.example.com,192.168.1.40,exporter_linux,,,,TRUE,,,,
hybrid2.example.com,192.168.1.41,exporter_windows,,,,,TRUE,443,,
hybrid3.example.com,192.168.1.42,exporter_jmx,,,,,,9090,TRUE,TRUE
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
    standard exporters. It also handles exporter-specific port configurations and
    blackbox monitoring cases.
    """
    # Use the port mappings from configuration
    port_mappings = PORT_MAPPINGS.copy()
    
    # If configuration is empty, use hardcoded fallback mappings
    if not port_mappings:
        logger.warning("No port mappings found in configuration, using hardcoded defaults")
        port_mappings = {
            "exporter_linux": {
                "src": [("TCP", "22"), ("ICMP", "ping")],
                "dst": [],
            },
            "exporter_windows": {
                "src": [("TCP", "9182"), ("ICMP", "ping")],
                "dst": [("UDP", "514"), ("TCP", "514")],
            },
            # Add a few more essential defaults
            "exporter_network": {
                "src": [("UDP", "161"), ("ICMP", "ping")],
                "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
            }
        }
    else:
        # Convert the port mappings from the config format to tuple format expected by the code
        for exporter_name, mapping in port_mappings.items():
            if 'src' in mapping and isinstance(mapping['src'], list):
                src_ports = [tuple(port_entry) for port_entry in mapping['src']]
                port_mappings[exporter_name]['src'] = src_ports
            
            if 'dst' in mapping and isinstance(mapping['dst'], list):
                dst_ports = [tuple(port_entry) for port_entry in mapping['dst']]
                port_mappings[exporter_name]['dst'] = dst_ports
    
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

    # Get the form data for custom port configurations
    form_data = {}
    if request.form:
        form_data = request.form.to_dict(flat=False)

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
        for i, header_candidate_row in enumerate(all_rows[:min(10, len(all_rows))]):
            if any('FQDN' in str(cell).upper() for cell in header_candidate_row):
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
        for data_row in data_rows:
            if len(data_row) <= max(fqdn_index, ip_index):
                # Skip rows that don't have enough columns
                continue
                
            # Get FQDN and IP
            target_fqdn = data_row[fqdn_index].strip()
            ip = data_row[ip_index].strip()
            
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

            # Check for blackbox monitoring port configurations
            blackbox_ports = []
            
            # Check if this row has blackbox flags directly in the data
            # Use the column indices from the CSV file to get the values
            has_ssh_banner = False
            has_tcp_connect = False
            has_snmp = False
            has_ssl = False
            tcp_port_value = None
            
            # Get the column indices from headers if available
            header_columns = {}
            if "csv_columns" in session:
                header_columns = session.get("csv_columns", {})
            
            # Loop through all rows in the headers data to find this hostname
            all_rows = list(csv.reader(input_file))
            input_file.seek(0)  # Reset file position after reading
            
            # Find the header row
            header_row = None
            for i, header_candidate_row in enumerate(all_rows[:min(10, len(all_rows))]):
                if any('FQDN' in str(cell).upper() for cell in header_candidate_row):
                    header_row = i
                    break
            
            if header_row is not None:
                headers = all_rows[header_row]
                # Find indices for important columns
                ssh_banner_idx = None
                tcp_connect_idx = None
                tcp_port_idx = None
                snmp_idx = None
                ssl_idx = None
                fqdn_idx = None
                
                for i, header in enumerate(headers):
                    header_upper = str(header).upper()
                    if 'FQDN' in header_upper:
                        fqdn_idx = i
                    elif 'SSH-BANNER' in header_upper.replace('_', '-'):
                        ssh_banner_idx = i
                    elif 'TCP-CONNECT' in header_upper.replace('_', '-') and 'PORT' not in header_upper:
                        tcp_connect_idx = i
                    elif 'TCP' in header_upper and 'CONNECT' in header_upper and 'PORT' in header_upper:
                        tcp_port_idx = i
                    elif 'SNMP' in header_upper:
                        snmp_idx = i
                    elif 'SSL' in header_upper or 'EXPORTER_SSL' in header_upper:
                        ssl_idx = i
                
                # Search for this hostname in the data rows
                for search_row in all_rows[header_row + 1:]:
                    if len(search_row) <= fqdn_idx:
                        continue
                    
                    if search_row[fqdn_idx].strip() == target_fqdn:
                        # Check SSH Banner
                        if ssh_banner_idx is not None and ssh_banner_idx < len(search_row):
                            value = search_row[ssh_banner_idx].strip().lower()
                            if value in ('1', 'true', 'yes', 'y', 't'):
                                has_ssh_banner = True
                        
                        # Check TCP Connect
                        if tcp_connect_idx is not None and tcp_connect_idx < len(search_row):
                            value = search_row[tcp_connect_idx].strip().lower()
                            if value in ('1', 'true', 'yes', 'y', 't'):
                                has_tcp_connect = True
                        
                        # Check TCP Port
                        if tcp_port_idx is not None and tcp_port_idx < len(search_row):
                            value = search_row[tcp_port_idx].strip()
                            if value and value not in ('0', 'false', 'no', 'n', ''):
                                tcp_port_value = value
                        
                        # Check SNMP
                        if snmp_idx is not None and snmp_idx < len(search_row):
                            value = search_row[snmp_idx].strip().lower()
                            if value in ('1', 'true', 'yes', 'y', 't'):
                                has_snmp = True
                        
                        # Check SSL
                        if ssl_idx is not None and ssl_idx < len(search_row):
                            value = search_row[ssl_idx].strip().lower()
                            if value in ('1', 'true', 'yes', 'y', 't'):
                                has_ssl = True
                        
                        break  # Found the target row, no need to continue
            
            # First try to get ports from form data
            # SSH Banner monitoring
            ssh_banner_port_key = f"ssh_banner_port_{target_fqdn}"
            if ssh_banner_port_key in form_data:
                port = form_data[ssh_banner_port_key][0].strip()
                if port:
                    blackbox_ports.append(("TCP", port, "SSH Banner"))
            elif has_ssh_banner:
                # Use default port if flag is set but no port is in form data
                blackbox_ports.append(("TCP", "22", "SSH Banner"))
            
            # TCP Connect monitoring
            tcp_connect_port_key = f"tcp_connect_port_{target_fqdn}"
            if tcp_connect_port_key in form_data:
                port = form_data[tcp_connect_port_key][0].strip()
                if port and port.lower() not in ('true', 'yes', '1', 't', 'y'):
                    blackbox_ports.append(("TCP", port, "TCP Connect"))
                else:
                    # Default or from TCP_Connect_Port
                    port = tcp_port_value or "3389"
                    blackbox_ports.append(("TCP", port, "TCP Connect"))
            elif has_tcp_connect:
                # Use custom port from CSV or default
                port = tcp_port_value or "3389"
                blackbox_ports.append(("TCP", port, "TCP Connect"))
            elif tcp_port_value:
                # If there's a TCP port value but no flag, still use it
                blackbox_ports.append(("TCP", tcp_port_value, "TCP Connect"))
            
            # SNMP monitoring
            snmp_port_key = f"snmp_port_{target_fqdn}"
            if snmp_port_key in form_data:
                port = form_data[snmp_port_key][0].strip()
                if port and port.lower() not in ('true', 'yes', '1', 't', 'y'):
                    blackbox_ports.append(("UDP", port, "SNMP"))
                else:
                    # Use default port if value is invalid or a boolean flag
                    blackbox_ports.append(("UDP", "161", "SNMP"))
            elif has_snmp:
                # Use default port if flag is set but no port is in form data
                blackbox_ports.append(("UDP", "161", "SNMP"))
            
            # SSL monitoring
            ssl_port_key = f"ssl_port_{target_fqdn}"
            if ssl_port_key in form_data:
                port = form_data[ssl_port_key][0].strip()
                if port and port.lower() not in ('true', 'yes', '1', 't', 'y'):
                    blackbox_ports.append(("TCP", port, "SSL"))
                else:
                    # Use default port if value is invalid or a boolean flag
                    blackbox_ports.append(("TCP", "443", "SSL"))
            elif has_ssl:
                # Use default port if flag is set but no port is in form data
                blackbox_ports.append(("TCP", "443", "SSL"))
            
            # Add blackbox monitoring entries
            for protocol, port, monitor_type in blackbox_ports:
                description = f"Monitoring from {maas_ng_fqdn} to {target_fqdn} ({monitor_type})"
                entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, protocol, port, description)
                if entry not in unique_entries:
                    writer.writerow(entry)
                    unique_entries.add(entry)
                    processed_count += 1
            
            # Collect all exporter names using the column mappings configuration
            exporters = []
            
            # Access the data_row from the outer loop for exporter detection
            # This processes the current row we're on in the outer data_rows loop
            
            # First try using the column mappings from the configuration
            for exporter_name, config in COLUMN_MAPPINGS.items():
                column_names = []
                
                # Get column names for this exporter type
                if 'column_name' in config:
                    column_names = [config['column_name']]
                elif 'column_names' in config:
                    column_names = config['column_names']
                
                # Check each column name
                for col_name in column_names:
                    for i, header in enumerate(headers):
                        if i >= len(data_row):
                            continue
                        # Case-insensitive comparison
                        if col_name.upper() == str(header).upper() and data_row[i].strip():
                            exporters.append(data_row[i].strip())
            
            # If no exporters found using column mappings, fall back to generic approach
            if not exporters:
                logger.info(f"No exporters found using column mappings for {target_fqdn}, using fallback method")
                for i, header in enumerate(headers):
                    if i >= len(data_row):
                        continue
                    if 'EXPORTER' in str(header).upper() and data_row[i].strip():
                        exporters.append(data_row[i].strip())

            # Process each exporter
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
                    # Check for custom port configuration for this exporter in the form data
                    to_target_key = f"exporter_to_{exporter}_{target_fqdn}"
                    from_target_key = f"exporter_from_{exporter}_{target_fqdn}"
                    
                    # Get custom configured ports if present
                    has_custom_config = False
                    to_target_ports = []
                    from_target_ports = []
                    
                    if to_target_key in form_data:
                        custom_ports = form_data[to_target_key][0].strip()
                        if custom_ports:
                            has_custom_config = True
                            # Split comma-separated ports and create a list of TCP ports
                            # Don't include ICMP ping here - those come from default mappings
                            to_target_ports = [("TCP", port.strip()) for port in custom_ports.split(',') 
                                              if port.strip() and port.strip().lower() != 'ping']
                    
                    if from_target_key in form_data:
                        custom_ports = form_data[from_target_key][0].strip()
                        if custom_ports:
                            has_custom_config = True
                            # Split comma-separated ports and create a list of TCP ports
                            from_target_ports = [("TCP", port.strip()) for port in custom_ports.split(',') 
                                                if port.strip() and port.strip().lower() != 'ping']
                    
                    # Use custom port configuration if provided, otherwise use defaults
                    if has_custom_config:
                        # If we have a custom config, use it (completely replacing defaults)
                        src_ports = to_target_ports
                        dst_ports = from_target_ports
                    else:
                        # Otherwise use defaults
                        src_ports = port_mappings[exporter_key]["src"]
                        dst_ports = port_mappings[exporter_key]["dst"]
                    
                    # Add entries for source to destination (monitoring server to target)
                    for protocol, port in src_ports:
                        description = f"Monitoring from {maas_ng_fqdn} to {target_fqdn} ({exporter})"
                        entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, protocol, port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1

                    # Add entries for destination to source (target to monitoring server)
                    for protocol, port in dst_ports:
                        description = f"Return traffic from {target_fqdn} to {maas_ng_fqdn} ({exporter})"
                        entry = (target_fqdn, ip, maas_ng_fqdn, maas_ng_ip, protocol, port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1
                else:
                    logger.warning(f"Unknown exporter type: {exporter} for {target_fqdn}")

            # Process additional custom ports (always available)
            to_target_key = f"to_target_{target_fqdn}"
            from_target_key = f"from_target_{target_fqdn}"
            
            # Get custom ports from form data
            if to_target_key in form_data:
                custom_ports = form_data[to_target_key][0].strip()
                if custom_ports:
                    # Filter out non-numeric ports (like 'ping' which should be handled separately)
                    ports = [port.strip() for port in custom_ports.split(',') 
                             if port.strip() and port.strip().lower() != 'ping']
                    
                    # Check for duplicates with blackbox monitoring entries
                    blackbox_port_values = [port for protocol, port, _ in blackbox_ports]
                    
                    # Only add ports that aren't already covered by blackbox monitoring
                    # Make sure to check both port numbers and protocol
                    # We also need to track which blackbox ports already have entries
                    blackbox_port_entries = [(protocol, port) for protocol, port, _ in blackbox_ports]
                    
                    # Filter out ports that match blackbox monitoring entries
                    unique_ports = [p for p in ports if not any(p == entry[1] for entry in blackbox_port_entries)]
                    
                    for port in unique_ports:
                        description = f"Custom monitoring from {maas_ng_fqdn} to {target_fqdn}"
                        entry = (maas_ng_fqdn, maas_ng_ip, target_fqdn, ip, "TCP", port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1
                            logger.info(f"Added custom to_target port {port} for {target_fqdn}")
            
            if from_target_key in form_data:
                custom_ports = form_data[from_target_key][0].strip()
                if custom_ports:
                    # Filter out non-numeric ports (like 'ping')
                    ports = [port.strip() for port in custom_ports.split(',') 
                             if port.strip() and port.strip().lower() != 'ping']
                    for port in ports:
                        description = f"Custom return traffic from {target_fqdn} to {maas_ng_fqdn}"
                        entry = (target_fqdn, ip, maas_ng_fqdn, maas_ng_ip, "TCP", port, description)
                        if entry not in unique_entries:
                            writer.writerow(entry)
                            unique_entries.add(entry)
                            processed_count += 1
                            logger.info(f"Added custom from_target port {port} for {target_fqdn}")

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
                
                # Check TCP Connect
                if tcp_connect_index is not None and tcp_connect_index < len(row):
                    orig_value = row[tcp_connect_index].strip()
                    value = orig_value.lower()
                    if value in ('1', 'true', 'yes', 'y', 't'):
                        monitoring_flags['tcp_connect'] = orig_value  # Keep original value
                        if not has_exporters:
                            is_edge_case = True
                        logger.info(f"Detected TCP Connect for {row[fqdn_index]}: {orig_value}")
                
                # Check TCP Port
                if tcp_port_index is not None and tcp_port_index < len(row):
                    value = row[tcp_port_index].strip()
                    if value and value not in ('0', 'false', 'no', 'n', ''):
                        monitoring_flags['tcp_port'] = value
                        if not has_exporters:
                            is_edge_case = True
                        logger.info(f"Detected TCP Port for {row[fqdn_index]}: {value}")
                
                # Check SNMP
                if snmp_index is not None and snmp_index < len(row):
                    orig_value = row[snmp_index].strip()
                    value = orig_value.lower()
                    if value in ('1', 'true', 'yes', 'y', 't'):
                        monitoring_flags['snmp'] = orig_value  # Keep original value
                        if not has_exporters:
                            is_edge_case = True
                        logger.info(f"Detected SNMP for {row[fqdn_index]}: {orig_value}")
                
                # Check SSL
                if ssl_index is not None and ssl_index < len(row):
                    orig_value = row[ssl_index].strip()
                    value = orig_value.lower()
                    if value in ('1', 'true', 'yes', 'y', 't'):
                        monitoring_flags['ssl'] = orig_value  # Keep original value
                        if not has_exporters:
                            is_edge_case = True
                        logger.info(f"Detected SSL for {row[fqdn_index]}: {orig_value}")
                
                # Create suggested to_target and from_target ports
                to_target_ports = []
                from_target_ports = []
                
                # Create a dictionary of suggested ports
                suggested_ports = {}
                
                # Set default port suggestions for blackbox monitoring
                suggested_ports['ssh_banner'] = '22'
                suggested_ports['tcp_connect'] = monitoring_flags['tcp_port'] or '3389'
                suggested_ports['snmp'] = '161'
                suggested_ports['ssl'] = '443'
                
                # Add ports to the lists
                if monitoring_flags['ssh_banner']:
                    to_target_ports.append('22')
                
                if monitoring_flags['tcp_connect']:
                    to_target_ports.append(suggested_ports['tcp_connect'])
                
                if monitoring_flags['tcp_port']:
                    to_target_ports.append(monitoring_flags['tcp_port'])
                
                if monitoring_flags['ssl']:
                    to_target_ports.append('443')
                
                if monitoring_flags['snmp']:
                    to_target_ports.append('161')
                    from_target_ports.append('162')
                
                # Get exporter data
                exporters = []
                for idx in exporter_indices:
                    if idx < len(row) and row[idx].strip():
                        exporter_name = row[idx].strip()
                        exporters.append(exporter_name)
                        
                        # Add suggested ports from configuration for this exporter (if available)
                        if exporter_name in PORT_MAPPINGS:
                            exporter_ports = {
                                'src': PORT_MAPPINGS[exporter_name].get('src', []),
                                'dst': PORT_MAPPINGS[exporter_name].get('dst', [])
                            }
                            
                            # Add to suggested ports dictionary
                            suggested_ports[exporter_name] = exporter_ports
                
                # Add host to the list
                hostnames.append(fqdn)
                host_info = {
                    'fqdn': fqdn,
                    'ip': ip,
                    'exporters': exporters,
                    'is_edge_case': is_edge_case,
                    'suggested_ports': suggested_ports
                }
                
                # Always add monitoring flags to host_info
                # This ensures hybrid servers (with both exporters and monitoring flags) are properly processed
                host_info.update({
                    'monitoring_flags': monitoring_flags,
                    'suggested_to_target': ','.join(to_target_ports),
                    'suggested_from_target': ','.join(from_target_ports),
                    'ssh_banner': monitoring_flags['ssh_banner'],
                    'tcp_connect': monitoring_flags['tcp_connect'],
                    'tcp_port': monitoring_flags['tcp_port'],
                    'snmp': monitoring_flags['snmp'],
                    'ssl': monitoring_flags['ssl']
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
    """Process CSV and generate output file with port configurations from UI."""
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
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "firewall_check.sh")
        
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

@app.route("/config_status", methods=["GET"])
def config_status():
    """Display information about the current configuration."""
    return render_template(
        "config_status.html",
        config_info=APP_CONFIG_INFO,
        port_mappings=PORT_MAPPINGS,
        column_mappings=COLUMN_MAPPINGS
    )

@app.route("/api/port_mappings", methods=["GET", "POST"])
def port_mappings_api():
    """API endpoint for getting and setting custom port mappings."""
    # Use port mappings from configuration
    default_port_mappings = PORT_MAPPINGS.copy()
    
    # If configuration is empty, use a minimal fallback set
    if not default_port_mappings:
        logger.warning("No port mappings found in configuration for API, using fallback defaults")
        default_port_mappings = {
            "exporter_linux": {
                "src": [("TCP", "22"), ("ICMP", "ping")],
                "dst": [],
            },
            "exporter_windows": {
                "src": [("TCP", "9182"), ("ICMP", "ping")],
                "dst": [("UDP", "514"), ("TCP", "514")],
            },
            "exporter_network": {
                "src": [("UDP", "161"), ("ICMP", "ping")],
                "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
            }
        }
    
    if request.method == "GET":
        # Return the port mappings as JSON
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

@app.route('/export_config')
def export_config():
    """Export the current configuration as a YAML file."""
    try:
        # Create a config object with port and column mappings
        config = {
            'port_mappings': {},
            'column_mappings': {}
        }
        
        # Add all default port mappings
        # Convert tuples to lists for proper YAML serialization
        for exporter, mappings in PORT_MAPPINGS.items():
            config['port_mappings'][exporter] = {
                'src': [[protocol, port] for protocol, port in mappings.get('src', [])],
                'dst': [[protocol, port] for protocol, port in mappings.get('dst', [])]
            }
        
        # Add custom port mappings from session if they exist
        if 'custom_port_mappings' in session:
            config['port_mappings'].update(session['custom_port_mappings'])
            
        # Add column mappings
        config['column_mappings'].update(COLUMN_MAPPINGS)
        
        # Convert to YAML
        yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False)
        
        # Create response with YAML content
        response = make_response(yaml_content)
        response.headers['Content-Type'] = 'application/x-yaml'
        response.headers['Content-Disposition'] = 'attachment; filename=port_config.yaml'
        
        logger.info("Configuration exported as YAML")
        return response
        
    except Exception as e:
        logger.error(f"Error exporting configuration: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')