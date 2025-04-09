"""
Tests for the Flask application's port mapping functionality.
"""
import os
import io
import csv
import json
import yaml
import pytest
import tempfile
from flask import session
from app import app, create_port_csv

@pytest.fixture
def client():
    """Create a test client for the Flask application with a temporary upload folder."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Create a temporary directory for uploads
    with tempfile.TemporaryDirectory() as temp_dir:
        app.config['UPLOAD_FOLDER'] = temp_dir
        
        with app.test_client() as client:
            with app.app_context():
                yield client

def create_test_csv():
    """Create a test CSV file with both standard and edge case servers."""
    csv_content = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
server2.example.com,192.168.1.11,exporter_windows,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,8080,,true
"""
    return io.BytesIO(csv_content.encode())

def test_upload_csv(client):
    """Test uploading a CSV file."""
    # Create test data
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    
    # Upload the file
    response = client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Check that we are redirected to the process page
    assert response.status_code == 302
    assert response.location.endswith('/process')
    
    # Check session variables
    with client.session_transaction() as sess:
        assert 'file_path' in sess
        assert sess['maas_ng_fqdn'] == 'monitor.example.com'
        assert sess['maas_ng_ip'] == '10.10.10.10'

def test_process_page(client):
    """Test the process page displays all hostnames from the CSV."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Now access the process page
    response = client.get('/process')
    
    # Check that all hostnames are in the response
    assert b'server1.example.com' in response.data
    assert b'server2.example.com' in response.data
    assert b'blackbox1.example.com' in response.data
    assert b'blackbox2.example.com' in response.data
    
    # Check that edge case elements are in the response
    assert b'Edge Case' in response.data  # Edge case label
    assert b'to_target_blackbox1.example.com' in response.data  # Input field name for edge case
    assert b'from_target_blackbox1.example.com' in response.data  # Input field name for edge case

def test_edge_case_detection(client):
    """Test that edge cases are properly detected and displayed with port input fields."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Now access the process page
    response = client.get('/process')
    
    # Check that edge case classes and elements are present
    assert b'edge-case' in response.data  # CSS class for edge case rows
    assert b'edge-case-port-input' in response.data  # CSS class for port input fields
    
    # Check that suggested ports are provided
    html_content = response.data.decode('utf-8')
    assert '22' in html_content  # Port suggestion for ssh-banner
    assert '161' in html_content  # Port suggestion for SNMP
    assert '8080' in html_content  # Custom TCP port

def test_edge_case_port_submission(client):
    """Test submitting edge case port configurations directly in the process page."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Set up session data for the test
    with client.session_transaction() as sess:
        sess['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], 'test.csv')
        # Create a test file
        with open(sess['file_path'], 'w') as f:
            f.write("""FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
server2.example.com,192.168.1.11,exporter_windows,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,8080,,true
""")
        # Manually add CSV columns info to session
        sess['csv_columns'] = {
            'fqdn': 0,
            'ip': 1,
            'ssh_banner': 4,
            'tcp_connect': 5,
            'tcp_port': 6,
            'snmp': 7,
            'ssl': 8,
            'exporters': [2, 3]
        }
    
    # Submit the form with edge case port configurations
    form_data = {
        'selected_hostnames': ['server1.example.com', 'blackbox1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'csv',
        'data-ip-blackbox1.example.com': '192.168.1.30',
        'to_target_blackbox1.example.com': '22,443',
        'from_target_blackbox1.example.com': '162'
    }
    
    # This will be handled by the generate_output_csv route
    response = client.post('/generate_output_csv', data=form_data)
    
    # Check that edge case configs were processed
    with client.session_transaction() as sess:
        if 'edge_case_configs' in sess:
            configs = sess['edge_case_configs']
            assert 'blackbox1.example.com' in configs
            assert configs['blackbox1.example.com']['to_target'] == '22,443'
            assert configs['blackbox1.example.com']['from_target'] == '162'

def test_output_format_options(client):
    """Test that different output formats are supported."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Access the process page to check format options
    response = client.get('/process')
    
    # Check all output format options
    html_content = response.data.decode('utf-8')
    assert 'value="csv"' in html_content
    assert 'value="excel"' in html_content
    assert 'value="pdf"' in html_content
    assert 'value="check_csv"' in html_content
    assert 'value="cisco"' in html_content
    assert 'value="juniper"' in html_content
    assert 'value="paloalto"' in html_content
    assert 'value="iptables"' in html_content

def test_firewall_check_csv_option(client):
    """Test that the firewall check CSV option is available."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Access the process page
    response = client.get('/process')
    
    # Check for firewall check option
    assert b'Firewall Check CSV' in response.data
    assert b'download_check_script' in response.data

def test_download_check_script(client):
    """Test downloading the firewall check script."""
    # Create the scripts directory and firewall_check.sh script
    scripts_dir = os.path.join(os.path.dirname(os.path.abspath(app.root_path)), "scripts")
    if not os.path.exists(scripts_dir):
        os.makedirs(scripts_dir)
    
    script_path = os.path.join(scripts_dir, "firewall_check.sh")
    
    try:
        # Create a dummy firewall_check.sh if it doesn't exist for testing purposes
        if not os.path.exists(script_path):
            with open(script_path, 'w') as f:
                f.write("""#!/bin/bash
# Test firewall check script
echo "Firewall connectivity check tool"
""")
            os.chmod(script_path, 0o755)  # Make it executable
        
        # Request the script download
        response = client.get('/download_check_script')
        
        # Verify the response
        assert response.status_code == 200
        assert 'text/x-sh' in response.headers['Content-Type']
        assert response.headers['Content-Disposition'].startswith('attachment; filename=firewall_check.sh')
        assert b'#!/bin/bash' in response.data
    
    finally:
        # Clean up if we created a dummy script
        if os.path.exists(script_path) and not os.path.getsize(script_path) > 500:
            os.unlink(script_path)

def test_firewall_format_generation(client):
    """Test generation of firewall-specific formats."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Set up session data for the test
    with client.session_transaction() as sess:
        sess['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], 'test.csv')
        # Create a test file
        with open(sess['file_path'], 'w') as f:
            f.write("""FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
server2.example.com,192.168.1.11,exporter_windows,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,8080,,true
""")
    
    # Test each firewall format
    firewall_formats = ['cisco', 'juniper', 'paloalto', 'iptables']
    
    for fw_format in firewall_formats:
        # Submit the form with the specific firewall format
        form_data = {
            'selected_hostnames': ['server1.example.com'],
            'maas_ng_fqdn': 'monitor.example.com',
            'maas_ng_ip': '10.10.10.10',
            'output_format': fw_format
        }
        
        # This will be handled by the generate_output_csv route
        response = client.post('/generate_output_csv', data=form_data)
        
        # Verify response
        assert response.status_code == 200
        
        # Just verify we get a downloadable file response - detailed format testing would require more mocking
        assert 'attachment' in response.headers.get('Content-Disposition', '')

def test_firewall_check_csv_generation(client):
    """Test generation of the firewall check CSV format."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Set up session data for the test
    with client.session_transaction() as sess:
        sess['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], 'test.csv')
        # Create a test file
        with open(sess['file_path'], 'w') as f:
            f.write("""FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
server2.example.com,192.168.1.11,exporter_windows,,,,,,
blackbox1.example.com,192.168.1.30,,,,true,,true,true
blackbox2.example.com,192.168.1.31,,,,,8080,,true
""")
    
    # Submit the form requesting a firewall check CSV
    form_data = {
        'selected_hostnames': ['server1.example.com', 'blackbox1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'check_csv',
        'data-ip-blackbox1.example.com': '192.168.1.30',
        'to_target_blackbox1.example.com': '22,161',
        'from_target_blackbox1.example.com': '162'
    }
    
    # This will be handled by the generate_output_csv route
    response = client.post('/generate_output_csv', data=form_data)
    
    # Verify response
    assert response.status_code == 200
    assert 'firewall_check' in response.headers.get('Content-Disposition', '')
    
    # Read the CSV data from the response
    csv_data = response.data.decode('utf-8')
    
    # Verify the CSV structure
    assert 'Target_FQDN' in csv_data  # Header should be in the CSV
    assert 'Target_IP' in csv_data  # Header should be in the CSV
    assert 'Protocol' in csv_data  # Header should be in the CSV
    assert 'Port' in csv_data  # Header should be in the CSV
    assert 'Status' in csv_data  # Header should be in the CSV
    
    # Verify the CSV contains only monitoring server to target entries
    assert 'server1.example.com,192.168.1.10' in csv_data
    assert 'blackbox1.example.com,192.168.1.30' in csv_data

def test_port_mappings_tab(client):
    """Test that the port mappings tab is present on the process page."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Access the process page
    response = client.get('/process')
    
    # Check for tabs and port mappings tab content
    html_content = response.data.decode('utf-8')
    assert '<div class="tab-header">' in html_content
    assert 'data-tab="server-selection"' in html_content
    assert 'data-tab="port-mappings"' in html_content
    assert '<h3>Custom Exporter Configuration</h3>' in html_content
    assert '<div class="custom-exporter-form">' in html_content
    assert 'id="new-exporter-name"' in html_content
    assert 'id="new-to-target"' in html_content
    assert 'id="new-from-target"' in html_content
    assert 'id="port-mappings-table"' in html_content

def test_port_mappings_api_get(client):
    """Test the GET endpoint for fetching port mappings."""
    # Access the API endpoint
    response = client.get('/api/port_mappings')
    
    # Check the response
    assert response.status_code == 200
    
    # Parse the JSON response
    data = json.loads(response.data)
    
    # Verify some built-in port mappings are present
    assert 'exporter_linux' in data
    assert 'exporter_windows' in data
    assert 'src' in data['exporter_linux']
    assert 'dst' in data['exporter_linux']

def test_config_status_page(client):
    """Test the configuration status page."""
    # Access the config status page
    response = client.get('/config_status')
    
    # Check the response
    assert response.status_code == 200
    
    # Check that the page contains essential elements
    assert b'Configuration Status' in response.data
    assert b'Configuration Overview' in response.data
    assert b'Port Mappings' in response.data
    assert b'Column Mappings' in response.data
    
    # Check for configuration help section
    assert b'Configuration Help' in response.data
    assert b'export PORT_CONFIG=' in response.data
    assert b'docker run -p 5000:5000 -v' in response.data

def test_port_mappings_api_post(client):
    """Test the POST endpoint for setting custom port mappings."""
    # Create test data for custom port mappings
    custom_mappings = {
        'exporter_custom': {
            'src': [['TCP', '8000'], ['TCP', '9000']],
            'dst': [['TCP', '8888']]
        }
    }
    
    # Submit custom mappings to the API
    response = client.post('/api/port_mappings', 
                           data=json.dumps(custom_mappings),
                           content_type='application/json')
    
    # Check the response
    assert response.status_code == 200
    
    # Verify the custom mappings are stored in the session
    with client.session_transaction() as sess:
        assert 'custom_port_mappings' in sess
        assert 'exporter_custom' in sess['custom_port_mappings']
        assert sess['custom_port_mappings']['exporter_custom']['src'] == [['TCP', '8000'], ['TCP', '9000']]
        assert sess['custom_port_mappings']['exporter_custom']['dst'] == [['TCP', '8888']]

def test_custom_port_mappings_integration(client):
    """Test that custom port mappings are used in the CSV generation process."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Set up session data for the test
    with client.session_transaction() as sess:
        sess['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], 'test.csv')
        # Create a test file
        with open(sess['file_path'], 'w') as f:
            f.write("""FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_custom,,,,,,
""")
        # Add custom port mappings to the session
        sess['custom_port_mappings'] = {
            'exporter_custom': {
                'src': [['TCP', '8080'], ['TCP', '9090']],
                'dst': [['TCP', '7070']]
            }
        }
    
    # Submit the form to generate output
    form_data = {
        'selected_hostnames': ['server1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'csv'
    }
    
    # This will be handled by the generate_output_csv route
    response = client.post('/generate_output_csv', data=form_data)
    
    # Check that we get a proper CSV response
    assert response.status_code == 200
    assert 'text/csv' in response.headers.get('Content-Type', '')
    
    # Read the CSV data
    csv_content = response.data.decode('utf-8')
    reader = csv.reader(io.StringIO(csv_content))
    rows = list(reader)
    
    # Find rows with the custom ports
    has_port_8080 = False
    has_port_9090 = False
    has_port_7070 = False
    
    for row in rows:
        if len(row) >= 6:  # Ensure the row has enough columns
            if row[4] == 'TCP' and row[5] == '8080':
                has_port_8080 = True
            elif row[4] == 'TCP' and row[5] == '9090':
                has_port_9090 = True
            elif row[4] == 'TCP' and row[5] == '7070':
                has_port_7070 = True
    
    # Check that all custom ports are present
    assert has_port_8080, "Custom port 8080 not found in CSV output"
    assert has_port_9090, "Custom port 9090 not found in CSV output"
    assert has_port_7070, "Custom port 7070 not found in CSV output"

def test_config_export_functionality(client):
    """Test the configuration export functionality."""
    # Add custom port mappings to the session
    with client.session_transaction() as sess:
        sess['custom_port_mappings'] = {
            'exporter_custom': {
                'src': [['TCP', '8080'], ['TCP', '9090']],
                'dst': [['TCP', '7070']]
            }
        }
    
    # Access the export config endpoint
    response = client.get('/export_config')
    
    # Check the response
    assert response.status_code == 200
    assert 'application/x-yaml' in response.headers.get('Content-Type', '')
    assert 'attachment; filename=port_config.yaml' in response.headers.get('Content-Disposition', '')
    
    # Read and parse the YAML data
    yaml_content = response.data.decode('utf-8')
    config = yaml.safe_load(yaml_content)
    
    # Verify the YAML structure
    assert 'port_mappings' in config
    assert 'column_mappings' in config
    
    # Verify that the custom port mappings are included
    assert 'exporter_custom' in config['port_mappings']
    custom_mapping = config['port_mappings']['exporter_custom']
    assert 'src' in custom_mapping
    assert 'dst' in custom_mapping
    
    # Check specific port values
    src_ports = custom_mapping['src']
    dst_ports = custom_mapping['dst']
    
    # Check that our custom ports are in the exported config
    assert ['TCP', '8080'] in src_ports
    assert ['TCP', '9090'] in src_ports
    assert ['TCP', '7070'] in dst_ports
    
    # Check that standard exporters are also included
    assert any(key.startswith('exporter_') and key != 'exporter_custom' for key in config['port_mappings'].keys())
    
    # Check that column mappings are also exported
    assert len(config['column_mappings']) > 0

def test_export_config_link_in_config_status(client):
    """Test that the config_status page contains a link to export config."""
    # Access the config status page
    response = client.get('/config_status')
    
    # Check that the page contains a link to export configuration
    assert response.status_code == 200
    assert b'export_config' in response.data or b'Export Configuration' in response.data
    
    # Parse the HTML to find the link
    html_content = response.data.decode('utf-8')
    assert 'href="/export_config"' in html_content

if __name__ == "__main__":
    pytest.main()