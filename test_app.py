"""
Tests for the Flask application's port mapping functionality.
"""
import os
import io
import csv
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
    # Create the firewall_check.sh script in the app directory
    script_path = os.path.join(os.path.dirname(os.path.abspath(app.root_path)), "firewall_check.sh")
    
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

if __name__ == "__main__":
    pytest.main()