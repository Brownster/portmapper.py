"""
Configuration loader for the port mapper application.
Handles loading and parsing of YAML configuration files.
"""
import os
import logging
import sys
import yaml

logger = logging.getLogger(__name__)

# Default config paths in the application directory
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'port_config.yaml')

# Standard config paths to check
CONFIG_SEARCH_PATHS = [
    # Config directory
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'port_config.yaml'),
    # Current directory
    os.path.join(os.getcwd(), 'port_config.yaml'),
    # User config directory
    os.path.expanduser('~/.config/portmapper/config.yaml'),
    # System config directory
    '/etc/portmapper/config.yaml',
]

def load_config(config_path=None):
    """
    Load the configuration from a YAML file.
    
    Args:
        config_path (str, optional): Path to a custom configuration file.
                                   If not provided, searches standard locations.
    
    Returns:
        dict: The parsed configuration.
        str: The path of the loaded configuration file.
    
    Raises:
        FileNotFoundError: If no configuration file is found.
        yaml.YAMLError: If there's an error parsing the YAML file.
    """
    # Ordered list of paths to try
    paths_to_try = []
    
    # 1. Explicitly provided path has highest priority
    if config_path:
        paths_to_try.append(config_path)
        
    # 2. Add standard search paths
    paths_to_try.extend(CONFIG_SEARCH_PATHS)
    
    # 3. Default path has lowest priority
    paths_to_try.append(DEFAULT_CONFIG_PATH)
    
    # Track which paths we've tried (to avoid duplicates)
    tried_paths = set()
    
    # Try each path in order
    for path in paths_to_try:
        # Skip paths we've already tried
        if path in tried_paths:
            continue
            
        tried_paths.add(path)
        
        if os.path.exists(path):
            logger.info(f"Found configuration file at {path}")
            try:
                with open(path, 'r') as config_file:
                    config = yaml.safe_load(config_file)
                
                # Validate required sections are present
                if config is None:
                    logger.warning(f"Configuration file {path} is empty")
                    config = {}
                
                if 'port_mappings' not in config:
                    logger.warning(f"No port_mappings section found in {path}")
                    config['port_mappings'] = {}
                
                if 'column_mappings' not in config:
                    logger.warning(f"No column_mappings section found in {path}")
                    config['column_mappings'] = {}
                    
                port_count = len(config['port_mappings'])
                column_count = len(config['column_mappings'])
                logger.info(f"Successfully loaded configuration from {path} with {port_count} port mappings and {column_count} column mappings")
                
                # Return both the config and the path that was used
                return config
                
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML configuration in {path}: {e}")
                # Continue to the next path instead of failing
                continue
    
    # If we get here, we couldn't find a valid config file
    error_msg = f"No valid configuration file found. Tried: {', '.join(tried_paths)}"
    logger.error(error_msg)
    
    # Create and return a minimal default config
    logger.warning("Using minimal built-in defaults")
    return {
        'port_mappings': {},
        'column_mappings': {}
    }

def get_column_mappings(config):
    """
    Extract column mappings from the configuration.
    
    Args:
        config (dict): The loaded configuration.
    
    Returns:
        dict: A dictionary of column mappings by exporter type.
    """
    return config.get('column_mappings', {})

def get_port_mappings(config):
    """
    Extract port mappings from the configuration.
    
    Args:
        config (dict): The loaded configuration.
    
    Returns:
        dict: A dictionary of port mappings by exporter type.
    """
    return config.get('port_mappings', {})

def get_columns_for_exporter(config, exporter_name):
    """
    Get the column names to check for a specific exporter type.
    
    Args:
        config (dict): The loaded configuration.
        exporter_name (str): The name of the exporter type.
    
    Returns:
        list: A list of column names to check.
    """
    column_mappings = get_column_mappings(config)
    
    # If the exporter is not in the column mappings, return an empty list
    if exporter_name not in column_mappings:
        return []
    
    exporter_config = column_mappings[exporter_name]
    
    # Handle both single column name and multiple column names
    if 'column_name' in exporter_config:
        return [exporter_config['column_name']]
    elif 'column_names' in exporter_config:
        return exporter_config['column_names']
    
    return []