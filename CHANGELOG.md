# Changelog

All notable changes to WinProc MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-03

### Added
- Initial release of WinProc MCP
- Claude Code MCP server integration
- Standalone PowerShell CLI interface (`winproc-cli.ps1`)

### Discovery Tools
- `find_processes_by_name` - Find processes by name pattern with wildcard support
- `find_processes_by_service` - Find processes for any service pattern
- `find_processes_by_port` - Find processes listening on specific ports
- `get_all_listening_ports` - List all listening ports on the system
- `get_process_info` - Get detailed information about a process by PID
- `get_multiple_process_info` - Analyze multiple processes simultaneously
- `get_service_info` - Get detailed information about a Windows service

### Management Tools
- `kill_process` - Terminate a specific process by PID
- `kill_processes_by_port` - Kill all processes on specific ports
- `kill_multiple_processes` - Kill multiple processes by PIDs
- `stop_service` / `start_service` / `restart_service` - Windows service management
- Dry run mode (`dry_run` parameter) for safe operation previews
- UAC elevation for administrative operations

### Security Features
- UAC elevation only when required for administrative operations
- Confirmation prompts for all destructive operations
- Safe defaults with read-only operations requiring no elevation
- Process tree analysis to show impact before operations
- Audit logging to `winproc_audit.log` with rotating file handler

### Configuration
Environment variables for customized behavior:
| Variable | Default | Description |
|----------|---------|-------------|
| `WINPROC_TIMEOUT` | `30` | Standard operation timeout (seconds) |
| `WINPROC_ELEVATED_TIMEOUT` | `60` | Elevated operation timeout (seconds) |
| `WINPROC_AUDIT_LOG` | `winproc_audit.log` | Audit log file path |
| `WINPROC_AUDIT_ENABLED` | `true` | Enable/disable audit logging |

### Technical
- Python 3.8+ support
- PowerShell 5.1+ compatibility (7.x recommended)
- Windows 10/11 and Windows Server support
- MCP (Model Context Protocol) integration
- Comprehensive pytest test suite with async support
- Automatic setup script (`winproc_mcp_setup.py`)
