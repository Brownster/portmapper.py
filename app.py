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
            
            for i, header in enumerate(headers):
                if 'FQDN' in str(header).upper():
                    fqdn_index = i
                if 'IP' in str(header).upper() and 'ADDRESS' in str(header).upper():
                    ip_index = i
            
            if fqdn_index is None or ip_index is None:
                flash("Could not find required columns (FQDN and IP Address) in the CSV file", "error")
                return redirect(url_for("upload_csv"))
            
            # Process the data rows
            for row in data_rows:
                if len(row) > max(fqdn_index, ip_index):  # Make sure row has enough columns
                    fqdn = row[fqdn_index].strip()
                    ip = row[ip_index].strip()
                    
                    if fqdn and ip:  # Both FQDN and IP are non-empty
                        hostnames.append(fqdn)
                        hostnames_info.append({
                            'fqdn': fqdn,
                            'ip': ip
                        })
        
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
        
        # Handle different output formats
        if output_format == 'excel':
            logger.info("Generating Excel file")
            excel_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{output_basename}.xlsx")
            df = pd.read_csv(output_file_path)
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
            
            # Convert CSV to HTML for PDF
            df = pd.read_csv(output_file_path)
            
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
        logger.error(f"Error in generate_output_csv: {e}")
        flash(f"Error generating output file: {str(e)}", "error")
        return redirect(url_for("process"))

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

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true')