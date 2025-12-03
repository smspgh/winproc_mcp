"""
Pytest fixtures for WinProc MCP tests
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess


@pytest.fixture
def mock_powershell_success():
    """Mock successful PowerShell execution"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Success output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def mock_powershell_failure():
    """Mock failed PowerShell execution"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Command failed"
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def mock_powershell_timeout():
    """Mock PowerShell timeout"""
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=30)
        yield mock_run


@pytest.fixture
def mock_admin_check_true():
    """Mock admin privilege check returning True"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "True\n"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def mock_admin_check_false():
    """Mock admin privilege check returning False"""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "False\n"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run


@pytest.fixture
def sample_process_output():
    """Sample PowerShell output for process info"""
    return """=== Process Information for PID 1234 ===
Process Name: notepad
Memory Usage: 25.5 MB
Command Line: C:\\Windows\\System32\\notepad.exe
TCP Listening Ports:
  0.0.0.0:8080"""


@pytest.fixture
def sample_port_output():
    """Sample PowerShell output for port search"""
    return """=== Port Search: 8080 ===

Port 8080 (TCP):
  Process: node (PID: 5678)
  Address: 0.0.0.0:8080
  Parent Service: Not found"""


@pytest.fixture
def sample_service_output():
    """Sample PowerShell output for service search"""
    return """=== Service Search: Docker* ===

Service: Docker - Docker Desktop Service
Status: Running
Start Type: Automatic
Main Process: Docker Desktop (PID: 9876)
Memory Usage: 150.2 MB"""
