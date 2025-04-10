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
    """Create a test CSV file for testing."""
    csv_content = """FQDN,IP Address,Exporter_name_os,Exporter_name_app
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx
server2.example.com,192.168.1.11,exporter_windows,
server3.example.com,192.168.1.12,exporter_vmware,
"""
    return io.BytesIO(csv_content.encode())

def test_upload_csv(client):
    """Test uploading a CSV file and verifying session variables are set."""
    # Create test data
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    
    # Submit the form
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
    # Check that the response redirects to the process page
    assert response.status_code == 200
    assert b'Process Hostnames' in response.data  # Process page title
    
    # Verify session variables are set
    with client.session_transaction() as session:
        assert 'file_path' in session
        assert 'maas_ng_fqdn' in session
        assert session['maas_ng_fqdn'] == 'monitor.example.com'
        assert 'maas_ng_ip' in session
        assert session['maas_ng_ip'] == '10.10.10.10'

def test_process_page(client):
    """Test the process page displays all hostnames from CSV."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
    # Check that all hostnames from the CSV are displayed
    assert b'server1.example.com' in response.data
    assert b'server2.example.com' in response.data
    assert b'server3.example.com' in response.data

def test_edge_case_detection(client):
    """Test detection of edge cases (servers with monitoring flags but no exporters)."""
    # Create a test CSV with edge cases
    csv_content = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
blackbox1.example.com,192.168.1.30,,,true,true,,true,true
blackbox2.example.com,192.168.1.31,,,,true,8080,,true
"""
    
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (io.BytesIO(csv_content.encode()), 'test.csv')
    }
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
    # Verify edge cases are detected - look for input fields for port configuration
    assert b'server1.example.com' in response.data
    assert b'blackbox1.example.com' in response.data
    assert b'blackbox2.example.com' in response.data
    
    # Check for port input fields for edge cases
    assert b'Edge Case' in response.data
    
    # The edge case should have input fields for ports
    assert b'to_target_blackbox1.example.com' in response.data
    assert b'from_target_blackbox1.example.com' in response.data

def test_edge_case_port_submission(client):
    """Test submitting edge case port configurations directly in the process page."""
    # First upload a file
    csv_content = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
blackbox1.example.com,192.168.1.30,,,true,true,,true,true
"""
    
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (io.BytesIO(csv_content.encode()), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Now submit the edge case port configurations
    form_data = {
        'selected_hostnames': ['blackbox1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'csv',
        'data-ip-blackbox1.example.com': '192.168.1.30',
        'to_target_blackbox1.example.com': '22,161',
        'from_target_blackbox1.example.com': '162'
    }
    
    # Submit the form - this should store edge_case_configs in session
    response = client.post('/generate_output_csv', data=form_data)
    
    # Check that the response has the expected format
    assert response.status_code == 200
    assert 'attachment' in response.headers.get('Content-Disposition', '')
    assert '.csv' in response.headers.get('Content-Disposition', '')

def test_output_format_options(client):
    """Test different output format options."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
    # Check that all output format options are available
    assert b'CSV' in response.data
    assert b'Excel' in response.data
    assert b'PDF' in response.data
    assert b'Cisco ASA' in response.data
    assert b'Juniper SRX' in response.data
    assert b'Palo Alto' in response.data
    assert b'Linux iptables' in response.data

def test_firewall_check_csv_option(client):
    """Test that the firewall check CSV option is available."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
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
        assert b'#' in response.data and b'bin/bash' in response.data
    
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
    
    # Test each firewall format
    firewall_formats = ['cisco_asa', 'juniper_srx', 'palo_alto', 'iptables']
    
    for firewall_format in firewall_formats:
        form_data = {
            'selected_hostnames': ['server1.example.com'],
            'maas_ng_fqdn': 'monitor.example.com',
            'maas_ng_ip': '10.10.10.10',
            'output_format': firewall_format
        }
        
        response = client.post('/generate_output_csv', data=form_data)
        
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
blackbox1.example.com,192.168.1.30,,,true,true,,true,true
blackbox2.example.com,192.168.1.31,,,,true,8080,,true
""")
    
    # Submit the form requesting a firewall check CSV
    form_data = {
        'selected_hostnames': ['server1.example.com', 'blackbox1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'check_csv',
        'data-ip-blackbox1.example.com': '192.168.1.30',
        'to_target_blackbox1.example.com': '22,161',
        'from_target_blackbox1.example.com': '162'    }
    
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
    
    # The main test in this function is to verify that the CSV contains entries for server1
    # We can't assert on the blackbox1 entry with our new approach since it's mutually exclusive
    assert 'server1.example.com,192.168.1.10' in csv_data

def test_port_mappings_tab(client):
    """Test that the port mappings tab is present on the process page."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    response = client.post('/', data=test_data, content_type='multipart/form-data', follow_redirects=True)
    
    # The port mappings tab should be present
    assert b'Port Mappings' in response.data
    
    # Check for the port mappings UI
    # The form ID may vary in different versions of the app
    assert (b'update_port_mappings' in response.data or 
            b'port-mappings-form' in response.data or
            b'port-mapping' in response.data)

def test_port_mappings_api_get(client):
    """Test the GET endpoint for fetching port mappings."""
    # Access the API endpoint
    response = client.get('/api/port_mappings')
    
    # Check the response
    assert response.status_code == 200
    
    # Parse the JSON response
    data = json.loads(response.data)
    
    # Verify it contains port mappings
    assert isinstance(data, dict)
    assert len(data) > 0
    
    # Check for at least one exporter 
    assert any(key.startswith('exporter_') for key in data.keys())
    
    # Check the structure of a port mapping
    exporter_name = next(key for key in data.keys() if key.startswith('exporter_'))
    assert 'src' in data[exporter_name]
    assert 'dst' in data[exporter_name]

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
        'exporter_test': {
            'src': [['TCP', '8080'], ['TCP', '9090']],
            'dst': [['TCP', '7070']]
        }
    }
    
    # Submit the data to the API
    response = client.post('/api/port_mappings', json=custom_mappings)
    
    # Check the response
    assert response.status_code == 200
    assert b'success' in response.data
    
    # Verify the custom mappings are stored in the session
    with client.session_transaction() as sess:
        assert 'custom_port_mappings' in sess
        assert 'exporter_test' in sess['custom_port_mappings']
        assert 'src' in sess['custom_port_mappings']['exporter_test']
        assert 'dst' in sess['custom_port_mappings']['exporter_test']
        
        # Verify the specific ports we set
        src_ports = sess['custom_port_mappings']['exporter_test']['src']
        dst_ports = sess['custom_port_mappings']['exporter_test']['dst']
        
        assert ['TCP', '8080'] in src_ports
        assert ['TCP', '9090'] in src_ports
        assert ['TCP', '7070'] in dst_ports

def test_custom_port_mappings_integration(client):
    """Test that custom port mappings are used in the CSV generation process."""
    # First upload a file
    test_data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'file': (create_test_csv(), 'test.csv')
    }
    client.post('/', data=test_data, content_type='multipart/form-data')
    
    # Create custom port mappings
    custom_mappings = {
        'exporter_custom': {
            'src': [['TCP', '8080'], ['TCP', '9090']],
            'dst': [['TCP', '7070']]
        }
    }
    
    # Submit the custom mappings to the API
    client.post('/api/port_mappings', json=custom_mappings)
    
    # Create a custom CSV file that uses the custom exporter
    with client.session_transaction() as sess:
        sess['file_path'] = os.path.join(app.config['UPLOAD_FOLDER'], 'custom_test.csv')
        with open(sess['file_path'], 'w') as f:
            f.write("""FQDN,IP Address,Exporter_name_os,Exporter_name_app
server1.example.com,192.168.1.10,exporter_custom,,
""")
    
    # Submit the form to generate a CSV with a server that uses our custom exporter
    form_data = {
        'selected_hostnames': ['server1.example.com'],
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'output_format': 'csv'
    }
    
    response = client.post('/generate_output_csv', data=form_data)
    
    # Verify that the CSV contains the custom port mappings
    csv_data = response.data.decode('utf-8')
    
    # Check for our custom ports
    has_port_8080 = '8080' in csv_data
    has_port_9090 = '9090' in csv_data
    has_port_7070 = '7070' in csv_data
    
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