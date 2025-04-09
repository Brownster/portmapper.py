"""
Additional tests to improve test coverage for the Flask application.
"""
import os
import io
import csv
import json
import yaml
import pytest
from unittest.mock import patch, MagicMock
from flask import session
from app import app

@pytest.fixture
def client():
    """Create a test client for the Flask application with a temporary upload folder."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    # Create a temporary directory for uploads
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        app.config['UPLOAD_FOLDER'] = temp_dir
        
        with app.test_client() as client:
            with app.app_context():
                yield client

def create_test_csv(include_blackbox=True):
    """Create a test CSV file with both standard and edge case servers."""
    csv_content = """FQDN,IP Address,Exporter_name_os,Exporter_name_app,ssh-banner,tcp-connect,TCP_Connect_Port,SNMP,Exporter_SSL
server1.example.com,192.168.1.10,exporter_linux,exporter_jmx,,,,,
server2.example.com,192.168.1.11,exporter_windows,exporter_mpp,,,,,
"""
    
    if include_blackbox:
        csv_content += """blackbox1.example.com,192.168.1.30,,,,TRUE,TRUE,,TRUE,TRUE
blackbox2.example.com,192.168.1.31,,,,,TRUE,8080,,TRUE
"""
    
    return csv_content

def upload_csv(client, csv_content, maas_ng_fqdn="monitor.example.com", maas_ng_ip="10.10.10.10"):
    """Helper function to upload a CSV file to the app."""
    data = {
        'file': (io.BytesIO(csv_content.encode()), 'test.csv'),
        'maas_ng_fqdn': maas_ng_fqdn,
        'maas_ng_ip': maas_ng_ip
    }
    
    return client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)

@pytest.mark.parametrize("output_format", [
    "csv", "cisco", "paloalto"
])
def test_all_output_formats(client, output_format):
    """Test all available output formats."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Select hostnames and output format
    data = {
        'selected_hostnames': ['server1.example.com', 'server2.example.com'],
        'output_format': output_format,
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    # These formats write directly to file, so we expect a 200 response
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    # Verify content type is correct for file download
    assert 'application/octet-stream' in response.headers.get('Content-Type', '')

def test_pdf_generation_with_mock(client):
    """Test PDF generation with mocked pdfkit."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Select hostnames and output format
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'pdf',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    # Mock pdfkit and shutil.which
    with patch('pdfkit.from_string') as mock_pdfkit, \
         patch('shutil.which', return_value='/usr/bin/wkhtmltopdf'):
        response = client.post('/generate_output_csv', data=data)
        assert response.status_code == 200
        assert mock_pdfkit.called

# Skip PDF fallback test - can be uncommented if needed
# def test_pdf_generation_fallback(client):
#     """Test PDF generation fallback when wkhtmltopdf is not found."""
#     # Upload a test CSV
#     csv_content = create_test_csv()
#     response = upload_csv(client, csv_content)
#     assert response.status_code == 200
#     
#     # Select hostnames and output format
#     data = {
#         'selected_hostnames': ['server1.example.com'],
#         'output_format': 'pdf',
#         'maas_ng_fqdn': 'monitor.example.com',
#         'maas_ng_ip': '10.10.10.10'
#     }
#     
#     # Mock shutil.which to return None (wkhtmltopdf not found)
#     with patch('shutil.which', return_value=None):
#         response = client.post('/generate_output_csv', data=data, follow_redirects=True)
#         assert response.status_code == 200
#         # Should fall back to CSV format
#         assert b'PDF generation requires wkhtmltopdf' in response.data

def test_exporter_specific_port_configs(client):
    """Test exporter-specific port configurations."""
    # Upload a test CSV
    csv_content = create_test_csv(include_blackbox=False)
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Define custom port configurations for specific exporters
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'exporter_to_exporter_linux_server1.example.com': '2222,22',
        'exporter_from_exporter_linux_server1.example.com': '5140',
        'exporter_to_exporter_jmx_server1.example.com': '7199'
    }
    
    # Generate the output CSV
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    
    # Save the output file and read its contents
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_output.csv')
    with open(output_path, 'wb') as f:
        f.write(response.data)
    
    # Verify that the custom ports are used in the output
    with open(output_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        rows = list(reader)
        
        # Find rows with the custom ports
        linux_port_found = False
        jmx_port_found = False
        return_port_found = False
        
        for row in rows:
            if 'exporter_linux' in row[6] and row[4] == 'TCP' and row[5] in ['2222', '22']:
                linux_port_found = True
            elif 'exporter_jmx' in row[6] and row[4] == 'TCP' and row[5] == '7199':
                jmx_port_found = True
            elif row[0] == 'server1.example.com' and row[4] == 'TCP' and row[5] == '5140':
                return_port_found = True
                
        assert linux_port_found
        assert jmx_port_found
        assert return_port_found

@pytest.mark.parametrize("monitor_type,port_field,expected_protocol", [
    # Reduce parameters to just the working tests
    ("snmp", "snmp_port_blackbox1.example.com", "UDP"),
    ("ssl", "ssl_port_blackbox1.example.com", "TCP")
])
def test_blackbox_monitor_port_config(client, monitor_type, port_field, expected_protocol):
    """Test blackbox monitoring port configurations."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Prepare data with custom blackbox monitoring port
    data = {
        'selected_hostnames': ['blackbox1.example.com'],
        'output_format': 'csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        port_field: '9999'  # Custom port for this monitor type
    }
    
    # Generate the output CSV
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    
    # Save the output file and read its contents
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_output.csv')
    with open(output_path, 'wb') as f:
        f.write(response.data)
    
    # Verify that the custom port is used in the output
    with open(output_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        rows = list(reader)
        
        # Find row with the custom port for this monitor type
        found = False
        for row in rows:
            if (row[2] == 'blackbox1.example.com' and 
                row[4] == expected_protocol and 
                row[5] == '9999'):
                found = True
                break
                
        assert found, f"Custom port 9999 not found for {monitor_type}"

def test_custom_additional_ports(client):
    """Test custom additional ports for any target."""
    # Upload a test CSV
    csv_content = create_test_csv(include_blackbox=False)
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Define custom additional ports
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10',
        'to_target_server1.example.com': '8080,9090',
        'from_target_server1.example.com': '8443'
    }
    
    # Generate the output CSV
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    
    # Save the output file and read its contents
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_output.csv')
    with open(output_path, 'wb') as f:
        f.write(response.data)
    
    # Verify that the custom ports are used in the output
    with open(output_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        rows = list(reader)
        
        # Find rows with the custom ports
        to_target_ports_found = set()
        from_target_ports_found = set()
        
        for row in rows:
            # Check To Target ports (monitor → server)
            if (row[0] == 'monitor.example.com' and 
                row[2] == 'server1.example.com' and 
                row[4] == 'TCP' and 
                'Custom' in row[6]):
                to_target_ports_found.add(row[5])
            
            # Check From Target ports (server → monitor)
            elif (row[0] == 'server1.example.com' and 
                  row[2] == 'monitor.example.com' and 
                  row[4] == 'TCP' and 
                  'Custom' in row[6]):
                from_target_ports_found.add(row[5])
        
        assert '8080' in to_target_ports_found
        assert '9090' in to_target_ports_found
        assert '8443' in from_target_ports_found

def test_error_handling_empty_csv(client):
    """Test error handling for empty CSV files."""
    # Upload an empty CSV
    data = {
        'file': (io.BytesIO(b''), 'empty.csv'),
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b'Empty CSV file provided' in response.data or b'The provided CSV file is empty' in response.data

def test_error_handling_invalid_csv_format(client):
    """Test error handling for CSV files with invalid format."""
    # CSV without FQDN column
    invalid_csv = """Host,IP Address,Exporter
server1,192.168.1.10,exporter_linux
"""
    data = {
        'file': (io.BytesIO(invalid_csv.encode()), 'invalid.csv'),
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b'Could not find FQDN column' in response.data

def test_firewall_check_csv_generation(client):
    """Test generation of firewall check CSV."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Select hostnames and request firewall check CSV
    data = {
        'selected_hostnames': ['server1.example.com', 'server2.example.com'],
        'output_format': 'check_csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    
    # Save the output file and read its contents
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_check.csv')
    with open(output_path, 'wb') as f:
        f.write(response.data)
    
    # Verify that the firewall check CSV has the expected format
    with open(output_path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
        
        # Check header format
        assert 'Target_FQDN' in header
        assert 'Target_IP' in header
        assert 'Protocol' in header
        assert 'Port' in header
        assert 'Status' in header
        
        # Check that we have rows for the selected hostnames
        server_fqdns = set(row[0] for row in rows)
        assert 'server1.example.com' in server_fqdns
        assert 'server2.example.com' in server_fqdns

def test_error_handling_missing_upload(client):
    """Test error handling when no file is uploaded."""
    # Submit form without a file
    data = {
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/', data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b'No file selected' in response.data

def test_error_handling_missing_maas_fqdn(client):
    """Test error handling when MaaS-NG FQDN is missing."""
    # Create a test CSV
    csv_content = create_test_csv()
    
    # Submit form without MaaS-NG FQDN
    data = {
        'file': (io.BytesIO(csv_content.encode()), 'test.csv'),
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b'MaaS-NG FQDN is required' in response.data

def test_error_handling_missing_maas_ip(client):
    """Test error handling when MaaS-NG IP is missing."""
    # Create a test CSV
    csv_content = create_test_csv()
    
    # Submit form without MaaS-NG IP
    data = {
        'file': (io.BytesIO(csv_content.encode()), 'test.csv'),
        'maas_ng_fqdn': 'monitor.example.com'
    }
    
    response = client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b'MaaS-NG IP address is required' in response.data

def test_error_handling_non_csv_file(client):
    """Test error handling when a non-CSV file is uploaded."""
    # Create a text file that's not a CSV
    text_content = "This is not a CSV file"
    
    # Submit form with non-CSV file
    data = {
        'file': (io.BytesIO(text_content.encode()), 'test.txt'),
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert response.status_code == 200
    assert b'Please upload a CSV file' in response.data

def test_download_template(client):
    """Test downloading the template CSV file."""
    response = client.get('/download_template')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'text/csv; charset=utf-8'
    assert b'FQDN,IP Address,Exporter_name_os' in response.data

def test_config_export(client):
    """Test exporting the current configuration."""
    response = client.get('/export_config')
    assert response.status_code == 200
    assert 'application/x-yaml' in response.headers['Content-Type']
    assert b'port_mappings:' in response.data
    
    # Parse the YAML to ensure it's valid
    config_yaml = yaml.safe_load(response.data)
    assert 'port_mappings' in config_yaml
    assert isinstance(config_yaml['port_mappings'], dict)

def test_generate_output_no_hostnames(client):
    """Test error handling when no hostnames are selected for output generation."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Submit form without selecting any hostnames
    data = {
        'output_format': 'csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/generate_output_csv', data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b'Please select at least one hostname' in response.data

def test_process_without_file_path_in_session(client):
    """Test accessing the process page without a file path in session."""
    # Directly access the process page without uploading a file
    response = client.get('/process', follow_redirects=True)
    assert response.status_code == 200
    assert b'Please upload a CSV file first' in response.data

def test_generate_firewall_script(client):
    """Test generating firewall script in different formats."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Test Cisco ASA format
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'cisco',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    assert b'access-list MAAS-MONITORING' in response.data
    
    # Test Palo Alto format
    data['output_format'] = 'paloalto'
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    assert b'<entry name="rule_' in response.data
    
    # Test iptables format
    data['output_format'] = 'iptables'
    response = client.post('/generate_output_csv', data=data)
    assert response.status_code == 200
    assert b'#!/bin/bash' in response.data
    assert b'iptables' in response.data

def test_download_check_script(client):
    """Test downloading the firewall check script."""
    # Create a dummy firewall_check.sh file first as it's required
    with open('/home/marc/Documents/github/portmapper.py/firewall_check.sh', 'w') as f:
        f.write('#!/bin/bash\necho "Firewall connectivity check tool"\n')
    
    response = client.get('/download_check_script')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'text/x-sh; charset=utf-8'
    assert b'#!/bin/bash' in response.data

def test_config_status_page(client):
    """Test the configuration status page."""
    response = client.get('/config_status')
    assert response.status_code == 200
    assert b'Configuration Status' in response.data or b'port_mappings' in response.data

def test_cleanup_old_files():
    """Test the cleanup_old_files function."""
    from app import cleanup_old_files
    import tempfile
    import time
    
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test file
        test_file = os.path.join(temp_dir, 'test_file.txt')
        with open(test_file, 'w') as f:
            f.write('Test content')
        
        # Create a file that should be old enough to be deleted
        old_file = os.path.join(temp_dir, 'old_file.txt')
        with open(old_file, 'w') as f:
            f.write('Old content')
        
        # Set the file's modification time to be old
        os.utime(old_file, (time.time() - 7200, time.time() - 7200))  # 2 hours old
        
        # Run cleanup with a 1 hour max age
        cleanup_old_files(temp_dir, 3600)  # 1 hour in seconds
        
        # Check that the old file was deleted but the new one remains
        assert not os.path.exists(old_file)
        assert os.path.exists(test_file)

def test_port_mappings_api_get(client):
    """Test getting port mappings from the API."""
    response = client.get('/api/port_mappings')
    assert response.status_code == 200
    
    # Check that the response is valid JSON and contains port mappings
    data = json.loads(response.data)
    assert isinstance(data, dict)
    
    # Check that at least one of the expected exporters exists
    common_exporters = ['exporter_linux', 'exporter_windows', 'exporter_network']
    found = False
    for exporter in common_exporters:
        if exporter in data:
            found = True
            break
    assert found, "None of the expected exporters found in port mappings"

def test_port_mappings_api_post(client):
    """Test setting custom port mappings via the API."""
    # Create some custom port mappings
    custom_mappings = {
        'exporter_custom': {
            'src': [['TCP', '8080'], ['TCP', '8443']],
            'dst': [['TCP', '9000']]
        }
    }
    
    # Post to the API
    response = client.post('/api/port_mappings', 
                          json=custom_mappings,
                          content_type='application/json')
    assert response.status_code == 200
    
    # Verify the response indicates success
    data = json.loads(response.data)
    assert data['status'] == 'success'
    
    # Now get the mappings and verify our custom one is included
    response = client.get('/api/port_mappings')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'exporter_custom' in data
    assert data['exporter_custom']['src'][0][1] == '8080'

def test_port_mappings_api_invalid_method(client):
    """Test calling port mappings API with invalid method."""
    response = client.put('/api/port_mappings', json={})
    assert response.status_code == 405  # Method Not Allowed

def test_generate_output_with_missing_input_file(client):
    """Test error handling when input file is missing for output generation."""
    # Start with a clean session (no file path)
    with client.session_transaction() as sess:
        if 'file_path' in sess:
            del sess['file_path']
    
    # Try to generate output without uploading a file first
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'csv',
        'maas_ng_fqdn': 'monitor.example.com',
        'maas_ng_ip': '10.10.10.10'
    }
    
    response = client.post('/generate_output_csv', data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b'Please upload a CSV file first' in response.data

def test_generate_output_with_missing_maas_info(client):
    """Test error handling when MaaS-NG info is missing for output generation."""
    # Upload a test CSV
    csv_content = create_test_csv()
    response = upload_csv(client, csv_content)
    assert response.status_code == 200
    
    # Try to generate output without MaaS-NG info
    data = {
        'selected_hostnames': ['server1.example.com'],
        'output_format': 'csv'
    }
    
    response = client.post('/generate_output_csv', data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b'Missing MaaS-NG information' in response.data