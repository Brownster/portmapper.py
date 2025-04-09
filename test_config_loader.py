"""
Tests for the configuration loader module.
"""
import os
import tempfile
import pytest
import yaml
from config_loader import load_config, get_port_mappings, get_column_mappings, get_columns_for_exporter

@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        'column_mappings': {
            'exporter_test': {
                'column_name': 'Test_Column'
            },
            'exporter_multi': {
                'column_names': ['Column1', 'Column2']
            }
        },
        'port_mappings': {
            'exporter_test': {
                'src': [['TCP', '22'], ['ICMP', 'ping']],
                'dst': [['UDP', '514']]
            },
            'exporter_another': {
                'src': [['TCP', '443']],
                'dst': []
            }
        }
    }

@pytest.fixture
def config_file():
    """Create a temporary configuration file for testing."""
    config_data = {
        'column_mappings': {
            'exporter_test': {
                'column_name': 'Test_Column'
            },
            'exporter_multi': {
                'column_names': ['Column1', 'Column2']
            }
        },
        'port_mappings': {
            'exporter_test': {
                'src': [['TCP', '22'], ['ICMP', 'ping']],
                'dst': [['UDP', '514']]
            },
            'exporter_another': {
                'src': [['TCP', '443']],
                'dst': []
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

def test_load_config(config_file):
    """Test loading configuration from a file."""
    config = load_config(config_file)
    
    # Check that both sections are loaded
    assert 'column_mappings' in config
    assert 'port_mappings' in config
    
    # Check specific entries
    assert 'exporter_test' in config['column_mappings']
    assert 'exporter_another' in config['port_mappings']
    
    # Check data integrity
    assert config['column_mappings']['exporter_test']['column_name'] == 'Test_Column'
    assert config['port_mappings']['exporter_test']['src'] == [['TCP', '22'], ['ICMP', 'ping']]
    assert config['port_mappings']['exporter_test']['dst'] == [['UDP', '514']]

def test_load_config_nonexistent_file():
    """Test loading configuration from a non-existent file."""
    # When a nonexistent file is specified, load_config should return a config with fallbacks
    config = load_config('/path/to/nonexistent/file.yaml')
    
    # Check that we get a valid config
    assert isinstance(config, dict)
    assert 'port_mappings' in config
    assert 'column_mappings' in config
    assert isinstance(config['port_mappings'], dict)
    assert isinstance(config['column_mappings'], dict)
    
    # The config should contain valid data (either from fallbacks or from default config)
    # Here we just check that it's not empty since we know the defaults are populated
    assert len(config['port_mappings']) > 0 
    # Column mappings might be empty depending on implementation
    assert isinstance(config['column_mappings'], dict)

def test_load_config_with_missing_sections(tmpdir):
    """Test loading configuration with missing sections."""
    # Create a config file with only port_mappings
    config_data = {
        'port_mappings': {
            'exporter_test': {
                'src': [['TCP', '22']],
                'dst': []
            }
        }
    }
    
    config_path = tmpdir.join('incomplete_config.yaml')
    with open(config_path, 'w') as f:
        yaml.dump(config_data, f)
    
    config = load_config(config_path)
    
    # Check that the missing section is added as empty
    assert 'column_mappings' in config
    assert isinstance(config['column_mappings'], dict)
    assert len(config['column_mappings']) == 0
    
    # Check that the existing section is preserved
    assert 'port_mappings' in config
    assert 'exporter_test' in config['port_mappings']

def test_get_port_mappings(sample_config):
    """Test extracting port mappings from the configuration."""
    port_mappings = get_port_mappings(sample_config)
    
    # Check that we get the correct number of mappings
    assert len(port_mappings) == 2
    
    # Check specific entries
    assert 'exporter_test' in port_mappings
    assert 'exporter_another' in port_mappings
    
    # Check that the data is correct
    assert port_mappings['exporter_test']['src'] == [['TCP', '22'], ['ICMP', 'ping']]
    assert port_mappings['exporter_test']['dst'] == [['UDP', '514']]
    assert port_mappings['exporter_another']['src'] == [['TCP', '443']]
    assert port_mappings['exporter_another']['dst'] == []

def test_get_port_mappings_empty_config():
    """Test extracting port mappings from an empty configuration."""
    port_mappings = get_port_mappings({})
    
    # Check that we get an empty dict
    assert isinstance(port_mappings, dict)
    assert len(port_mappings) == 0

def test_get_column_mappings(sample_config):
    """Test extracting column mappings from the configuration."""
    column_mappings = get_column_mappings(sample_config)
    
    # Check that we get the correct number of mappings
    assert len(column_mappings) == 2
    
    # Check specific entries
    assert 'exporter_test' in column_mappings
    assert 'exporter_multi' in column_mappings
    
    # Check that the data is correct
    assert column_mappings['exporter_test']['column_name'] == 'Test_Column'
    assert column_mappings['exporter_multi']['column_names'] == ['Column1', 'Column2']

def test_get_column_mappings_empty_config():
    """Test extracting column mappings from an empty configuration."""
    column_mappings = get_column_mappings({})
    
    # Check that we get an empty dict
    assert isinstance(column_mappings, dict)
    assert len(column_mappings) == 0

def test_get_columns_for_exporter(sample_config):
    """Test getting column names for a specific exporter."""
    # Test single column exporter
    columns = get_columns_for_exporter(sample_config, 'exporter_test')
    assert len(columns) == 1
    assert columns[0] == 'Test_Column'
    
    # Test multi-column exporter
    columns = get_columns_for_exporter(sample_config, 'exporter_multi')
    assert len(columns) == 2
    assert 'Column1' in columns
    assert 'Column2' in columns
    
    # Test nonexistent exporter
    columns = get_columns_for_exporter(sample_config, 'exporter_nonexistent')
    assert len(columns) == 0

def test_get_columns_for_exporter_empty_config():
    """Test getting column names for a specific exporter from an empty configuration."""
    columns = get_columns_for_exporter({}, 'exporter_test')
    
    # Check that we get an empty list
    assert isinstance(columns, list)
    assert len(columns) == 0

def test_get_columns_for_exporter_invalid_mapping():
    """Test getting column names for an exporter with invalid mapping."""
    config = {
        'column_mappings': {
            'exporter_invalid': {
                # Missing both column_name and column_names
                'something_else': 'value'
            }
        }
    }
    
    columns = get_columns_for_exporter(config, 'exporter_invalid')
    
    # Check that we get an empty list
    assert isinstance(columns, list)
    assert len(columns) == 0