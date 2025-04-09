"""
Tests for the application's configuration loading and integration.
"""
import os
import io
import tempfile
import pytest
import yaml
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

@pytest.fixture
def temp_config_file():
    """Create a temporary configuration file for testing."""
    config_data = {
        'column_mappings': {
            'exporter_test': {
                'column_name': 'Test_Column'
            }
        },
        'port_mappings': {
            'exporter_test': {
                'src': [['TCP', '8888'], ['ICMP', 'ping']],
                'dst': [['UDP', '999']]
            }
        }
    }
    
    temp_file_path = tempfile.mktemp(suffix='.yaml')
    with open(temp_file_path, 'w') as temp_file:
        yaml.dump(config_data, temp_file)
    
    yield temp_file_path
    
    # Clean up
    if os.path.exists(temp_file_path):
        os.unlink(temp_file_path)

def create_test_csv():
    """Create a test CSV file with custom exporters."""
    csv_content = """FQDN,IP Address,Test_Column
server1.example.com,192.168.1.10,exporter_test
"""
    return io.BytesIO(csv_content.encode())

def test_app_loads_config():
    """Test that the application loads the configuration at startup."""
    # Check that the app configuration is available
    # Since this test doesn't modify globals, it should be safe
    
    # Import PORT_MAPPINGS and COLUMN_MAPPINGS inside the test function
    from app import PORT_MAPPINGS, COLUMN_MAPPINGS
    
    # Check that both are populated
    assert PORT_MAPPINGS is not None
    assert isinstance(PORT_MAPPINGS, dict)
    
    assert COLUMN_MAPPINGS is not None
    assert isinstance(COLUMN_MAPPINGS, dict)
    
    # Check that they contain entries
    assert len(PORT_MAPPINGS) > 0
    assert any(key.startswith('exporter_') for key in PORT_MAPPINGS.keys())

def test_port_mappings_api(client):
    """Test that the API returns port mappings."""
    # Access the API endpoint
    response = client.get('/api/port_mappings')
    
    # Check the response
    assert response.status_code == 200
    
    # Parse the JSON response
    data = response.json
    
    # Verify it contains expected mappings
    assert isinstance(data, dict)
    assert len(data) > 0
    assert any(key.startswith('exporter_') for key in data.keys())

def test_column_mappings_in_config():
    """Test the column mappings from the configuration."""
    # Import COLUMN_MAPPINGS inside the test function
    from app import COLUMN_MAPPINGS
    
    # Check if we have any mappings
    assert COLUMN_MAPPINGS is not None
    assert isinstance(COLUMN_MAPPINGS, dict)
    
    # If we have mappings, verify their structure
    if COLUMN_MAPPINGS:
        for exporter_name, mapping in COLUMN_MAPPINGS.items():
            # Each mapping should have column_name or column_names
            assert 'column_name' in mapping or 'column_names' in mapping
            
            if 'column_name' in mapping:
                assert isinstance(mapping['column_name'], str)
                
            if 'column_names' in mapping:
                assert isinstance(mapping['column_names'], list)
                assert all(isinstance(name, str) for name in mapping['column_names'])

if __name__ == "__main__":
    pytest.main()