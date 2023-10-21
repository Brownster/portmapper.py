from flask import Flask, request, redirect, url_for, flash, send_file, session, render_template
import io
import csv

# Function to create port CSV
def create_port_csv(input_file, output_file, maas_ng_ip, selected_hostnames=None):
    port_mappings = {
        "exporter_aes": {
            "src": [("TCP", "22"), ("UDP", "162")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_gateway": {
            "src": [("UDP", "161"), ("TCP", "22")],
            "dst": [("UDP", "162")],
        },
        "exporter_ams": {
            "src": [("TCP", "22"), ("UDP", "161")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_sm": {
            "src": [("TCP", "22")],
            "dst": [],
        },
        "exporter_avayasbc": {
            "src": [("TCP", "222"), ("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_aaep": {
            "src": [("TCP", "22"), ("TCP", "5432"), ("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_mpp": {
            "src": [("TCP", "22")],
            "dst": [],
        },
        "exporter_windows": {
            "src": [("TCP", "9182")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_linux": {
            "src": [("TCP", "22")],
            "dst": [],
        },
        "exporter_ipo": {
            "src": [("TCP", "22"), ("TCP", "8443")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_iq": {
            "src": [("TCP", "22")],
            "dst": [],
        },
        "exporter_weblm": {
            "src": [("TCP", "22")],
            "dst": [],
        },
        "exporter_aacc": {
            "src": [("TCP", "9182")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_wfodb": {
            "src": [("TCP", "1433"), ("TCP", "9182")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_verint": {
            "src": [("TCP", "9182")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_network": {
            "src": [("UDP", "161")],
            "dst": [("UDP", "162"), ("UDP", "514"), ("TCP", "514")],
        },
        "exporter_tcti": {
            "src": [("UDP", "514"), ("TCP", "514")],
            "dst": [],
        },
        "exporter_callback": {
            "src": [("TCP", "1433")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_nuance": {
            "src": [("TCP", "9182"), ("TCP", "27000")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_windows": {
            "src": [("TCP", "9182")],
            "dst": [("UDP", "514"), ("TCP", "514")],
        },
        "exporter_breeze": {
            "src": [("TCP", "22")],
            "dst": [],
        },


       }

    unique_entries = set()

    reader = csv.DictReader(input_file)
    writer = csv.writer(output_file)
    writer.writerow(["Source_IP_Address", "Destination_IP_Address", "Port"])

    for row in reader:
        fqdn = row["FQDN"]
        if selected_hostnames is not None and fqdn not in selected_hostnames:
            continue
            
        ip = row["IP Address"]
        exporter_name_os = row["Exporter_name_os"]
        exporter_name_app = row["Exporter_name_app"]

        exporters = [exporter_name_os, exporter_name_app]

        for exporter in exporters:
            if exporter in port_mappings:
                for protocol, port in port_mappings[exporter]["src"]:
                    entry = (maas_ng_ip, ip, f"{protocol}: {port}")
                    if entry not in unique_entries:
                        writer.writerow(entry)
                        unique_entries.add(entry)

                for protocol, port in port_mappings[exporter]["dst"]:
                    entry = (ip, maas_ng_ip, f"{protocol}: {port}")
                    if entry not in unique_entries:
                        writer.writerow(entry)
                        unique_entries.add(entry)

# Create Flask app and set the secret key
app = Flask(__name__)
app.secret_key = "your_secret_key"

# Route to upload CSV
@app.route("/", methods=["GET", "POST"])
def upload_csv():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected")
            return redirect(request.url)

        maas_ng_ip = request.form.get("maas_ng_ip")
        if not maas_ng_ip:
            flash("MaaS-NG IP address is required")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected")
            return redirect(request.url)

        if file:
            session['uploaded_csv'] = file.stream.read().decode("UTF8")
            return redirect(url_for("process", maas_ng_ip=maas_ng_ip))

    return render_template("index.html")

# Route to process the uploaded CSV
@app.route("/process")
def process():
    maas_ng_ip = request.args.get("maas_ng_ip")
    input_file = io.StringIO(session["uploaded_csv"], newline=None)

    hostnames = []
    reader = csv.DictReader(input_file)
    for row in reader:
        hostnames.append(row["FQDN"])

    return render_template("process.html", hostnames=hostnames, maas_ng_ip=maas_ng_ip)

# Route to generate the output CSV
@app.route("/generate_output_csv", methods=["POST"])
def generate_output_csv():
    selected_hostnames = request.form.getlist("selected_hostnames")
    maas_ng_ip = request.form["maas_ng_ip"]
    input_file = io.StringIO(session["uploaded_csv"], newline=None)
    output_file = io.StringIO()

    create_port_csv(input_file, output_file, maas_ng_ip, selected_hostnames)

    output_file.seek(0)
    return send_file(
        output_file,
        mimetype="text/csv",
        as_attachment=True,
        attachment_filename="output.csv",
    )

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)

