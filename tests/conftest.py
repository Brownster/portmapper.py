"""
Configuration file for pytest.
"""
import os
import sys

# Add the parent directory to the path so we can import app modules
# This is only used when running pytest directly from the tests directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))