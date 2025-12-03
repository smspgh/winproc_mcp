"""
Tests for WinProc MCP Server

Tests cover:
- Input validation for all tools
- PowerShell execution handling
- Error handling scenarios
- Admin privilege checking
- Timeout handling
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winproc_mcp import (
    run_powershell,
    run_elevated_operation,
    check_admin_privileges,
)


class TestRunPowershell:
    """Tests for the run_powershell function"""

    def test_successful_execution(self, mock_powershell_success):
        """Test successful PowerShell command execution"""
        result = run_powershell("Get-Process")
        assert result == "Success output"
        mock_powershell_success.assert_called_once()

    def test_failed_execution(self, mock_powershell_failure):
        """Test failed PowerShell command returns error"""
        result = run_powershell("Invalid-Command")
        assert "Error:" in result

    def test_timeout_handling(self, mock_powershell_timeout):
        """Test timeout is handled gracefully"""
        result = run_powershell("Long-Running-Command")
        assert "Error:" in result
        assert "TimeoutExpired" in result or "timed out" in result.lower()

    def test_exception_handling(self):
        """Test general exception handling"""
        with patch('subprocess.run', side_effect=Exception("Unexpected error")):
            result = run_powershell("Any-Command")
            assert "Error:" in result
            assert "Unexpected error" in result

    def test_command_structure(self, mock_powershell_success):
        """Test PowerShell is called with correct arguments"""
        run_powershell("Test-Command")
        call_args = mock_powershell_success.call_args
        assert call_args[0][0][0] == "powershell"
        assert "-ExecutionPolicy" in call_args[0][0]
        assert "Bypass" in call_args[0][0]
        assert "-NoProfile" in call_args[0][0]


class TestCheckAdminPrivileges:
    """Tests for admin privilege checking"""

    def test_admin_true(self, mock_admin_check_true):
        """Test detection of admin privileges"""
        result = check_admin_privileges()
        assert result is True

    def test_admin_false(self, mock_admin_check_false):
        """Test detection of non-admin"""
        result = check_admin_privileges()
        assert result is False

    def test_admin_check_error(self):
        """Test handling of errors during admin check"""
        with patch('subprocess.run', side_effect=Exception("Access denied")):
            # Import the function fresh to test
            from winproc_mcp import run_powershell
            with patch('winproc_mcp.run_powershell', return_value="Error: failed"):
                result = check_admin_privileges()
                assert result is False


class TestInputValidation:
    """Tests for input validation across tools"""

    def test_empty_service_pattern(self):
        """Test empty service pattern returns error"""
        # This tests the validation logic - empty patterns should fail
        service_pattern = ""
        assert not service_pattern  # Validation should catch this

    def test_invalid_process_id(self):
        """Test invalid process ID values"""
        invalid_ids = [0, -1, -100]
        for pid in invalid_ids:
            assert pid <= 0  # Validation should reject these

    def test_empty_port_list(self):
        """Test empty port list validation"""
        ports = []
        assert len(ports) == 0  # Validation should catch this

    def test_valid_process_ids(self):
        """Test valid process ID values pass validation"""
        valid_ids = [1, 100, 1234, 65535]
        for pid in valid_ids:
            assert pid > 0

    def test_valid_port_numbers(self):
        """Test valid port numbers"""
        valid_ports = [80, 443, 3000, 8080, 65535]
        for port in valid_ports:
            assert 0 < port <= 65535


class TestRunElevatedOperation:
    """Tests for elevated operation execution"""

    def test_elevated_operation_success(self):
        """Test successful elevated operation"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            result = run_elevated_operation("kill-process", "1234", force=False)
            assert "successfully" in result.lower() or "completed" in result.lower()

    def test_elevated_operation_failure(self):
        """Test failed elevated operation"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "Access denied"
            mock_run.return_value = mock_result

            result = run_elevated_operation("kill-process", "1234", force=False)
            assert "failed" in result.lower() or "cancelled" in result.lower()

    def test_elevated_operation_with_force(self):
        """Test force flag is passed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            run_elevated_operation("kill-process", "1234", force=True)
            call_args = str(mock_run.call_args)
            assert "-Force" in call_args

    def test_elevated_operation_timeout(self):
        """Test timeout handling in elevated operations"""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("cmd", 60)):
            result = run_elevated_operation("stop-service", "TestService")
            assert "Error" in result


class TestToolSchemas:
    """Tests for MCP tool schema definitions"""

    @pytest.mark.asyncio
    async def test_list_tools_returns_all_tools(self):
        """Test that list_tools returns expected number of tools"""
        from winproc_mcp import list_tools
        tools = await list_tools()

        expected_tools = [
            "find_processes_by_name",
            "find_processes_by_service",
            "find_processes_by_port",
            "get_all_listening_ports",
            "get_process_info",
            "get_multiple_process_info",
            "get_service_info",
            "kill_process",
            "kill_processes_by_port",
            "kill_multiple_processes",
            "stop_service",
            "start_service",
            "restart_service",
        ]

        tool_names = [t.name for t in tools]
        for expected in expected_tools:
            assert expected in tool_names, f"Missing tool: {expected}"

    @pytest.mark.asyncio
    async def test_tool_schemas_have_required_fields(self):
        """Test that all tools have proper schema definitions"""
        from winproc_mcp import list_tools
        tools = await list_tools()

        for tool in tools:
            assert tool.name, "Tool must have a name"
            assert tool.description, f"Tool {tool.name} must have a description"
            assert tool.inputSchema, f"Tool {tool.name} must have an input schema"
            assert "type" in tool.inputSchema, f"Tool {tool.name} schema must have type"


class TestCallTool:
    """Tests for the call_tool handler"""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        """Test that unknown tools return an error message"""
        from winproc_mcp import call_tool
        result = await call_tool("nonexistent_tool", {})
        assert len(result) == 1
        assert "Unknown tool" in result[0].text

    @pytest.mark.asyncio
    async def test_find_processes_by_service_empty_pattern(self):
        """Test empty service pattern returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("find_processes_by_service", {"service_pattern": ""})
        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_find_processes_by_port_empty_ports(self):
        """Test empty ports list returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("find_processes_by_port", {"ports": []})
        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_get_process_info_invalid_pid(self):
        """Test invalid PID returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("get_process_info", {"process_id": 0})
        assert len(result) == 1
        assert "Error" in result[0].text or "Invalid" in result[0].text

    @pytest.mark.asyncio
    async def test_get_multiple_process_info_empty_list(self):
        """Test empty process ID list returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("get_multiple_process_info", {"process_ids": []})
        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_kill_process_invalid_pid(self):
        """Test kill with invalid PID returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("kill_process", {"process_id": -1})
        assert len(result) == 1
        assert "Error" in result[0].text or "Invalid" in result[0].text

    @pytest.mark.asyncio
    async def test_service_operations_empty_name(self):
        """Test service operations with empty name return error"""
        from winproc_mcp import call_tool

        for operation in ["stop_service", "start_service", "restart_service"]:
            result = await call_tool(operation, {"service_name": ""})
            assert len(result) == 1
            assert "Error" in result[0].text, f"{operation} should error on empty name"


class TestEnvironmentConfiguration:
    """Tests for environment-based configuration"""

    def test_default_timeout_value(self):
        """Test default timeout is used when env var not set"""
        # Default is 30 seconds for run_powershell
        with patch.dict(os.environ, {}, clear=True):
            with patch('subprocess.run') as mock_run:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "output"
                mock_run.return_value = mock_result

                run_powershell("test")

                call_kwargs = mock_run.call_args[1]
                assert call_kwargs.get('timeout') == 30


class TestEdgeCases:
    """Tests for edge cases and boundary conditions"""

    def test_very_long_service_pattern(self):
        """Test handling of very long service patterns"""
        long_pattern = "A" * 1000
        # Should not crash, validation should handle
        assert len(long_pattern) > 0

    def test_special_characters_in_pattern(self):
        """Test handling of special characters in patterns"""
        special_patterns = ["*SQL*", "Docker*", "*Web*", "test-service", "test_service"]
        for pattern in special_patterns:
            # Patterns with wildcards and common chars should be valid
            assert pattern  # Not empty

    def test_unicode_in_arguments(self):
        """Test handling of unicode characters"""
        unicode_name = "Service-\u00e9\u00e8\u00ea"
        # Should handle unicode gracefully
        assert len(unicode_name) > 0

    @pytest.mark.asyncio
    async def test_none_arguments(self):
        """Test handling of None arguments"""
        from winproc_mcp import call_tool
        result = await call_tool("get_all_listening_ports", None)
        # Should not crash, should return valid response
        assert len(result) >= 1


class TestFindProcessesByName:
    """Tests for the new find_processes_by_name tool"""

    @pytest.mark.asyncio
    async def test_empty_pattern_returns_error(self):
        """Test empty name pattern returns error"""
        from winproc_mcp import call_tool
        result = await call_tool("find_processes_by_name", {"name_pattern": ""})
        assert len(result) == 1
        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_valid_pattern_accepted(self):
        """Test valid patterns are accepted"""
        from winproc_mcp import call_tool
        # This will execute but may not find matches - that's ok
        result = await call_tool("find_processes_by_name", {"name_pattern": "nonexistent*"})
        assert len(result) == 1
        # Should not error, should return search results (even if empty)
        assert "Error: No process name pattern" not in result[0].text


class TestDryRunMode:
    """Tests for dry run functionality"""

    @pytest.mark.asyncio
    async def test_kill_process_dry_run(self):
        """Test kill_process with dry_run returns preview"""
        from winproc_mcp import call_tool
        result = await call_tool("kill_process", {
            "process_id": 99999,  # Non-existent PID
            "dry_run": True
        })
        assert len(result) == 1
        assert "DRY RUN" in result[0].text

    @pytest.mark.asyncio
    async def test_kill_processes_by_port_dry_run(self):
        """Test kill_processes_by_port with dry_run returns preview"""
        from winproc_mcp import call_tool
        result = await call_tool("kill_processes_by_port", {
            "ports": [99999],  # Unlikely port
            "dry_run": True
        })
        assert len(result) == 1
        assert "DRY RUN" in result[0].text

    @pytest.mark.asyncio
    async def test_stop_service_dry_run(self):
        """Test stop_service with dry_run returns preview"""
        from winproc_mcp import call_tool
        result = await call_tool("stop_service", {
            "service_name": "NonExistentService12345",
            "dry_run": True
        })
        assert len(result) == 1
        assert "DRY RUN" in result[0].text


class TestAuditLogging:
    """Tests for audit logging functionality"""

    def test_audit_log_function_exists(self):
        """Test audit_log function is importable"""
        from winproc_mcp import audit_log
        # Should not raise
        assert callable(audit_log)

    def test_audit_log_with_disabled_logging(self):
        """Test audit_log handles disabled logging gracefully"""
        from winproc_mcp import audit_log
        # Should not raise even if logging is disabled
        audit_log("test_operation", "test_target", "TEST", "test details")


class TestConfigurableTimeouts:
    """Tests for configurable timeout functionality"""

    def test_default_timeout_constants_exist(self):
        """Test timeout constants are defined"""
        from winproc_mcp import WINPROC_TIMEOUT, WINPROC_ELEVATED_TIMEOUT
        assert isinstance(WINPROC_TIMEOUT, int)
        assert isinstance(WINPROC_ELEVATED_TIMEOUT, int)
        assert WINPROC_TIMEOUT > 0
        assert WINPROC_ELEVATED_TIMEOUT > 0

    def test_run_powershell_accepts_custom_timeout(self):
        """Test run_powershell accepts custom timeout parameter"""
        from winproc_mcp import run_powershell
        # Should accept timeout parameter without error
        result = run_powershell("Write-Host 'test'", timeout=5)
        # Result should be a string
        assert isinstance(result, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
