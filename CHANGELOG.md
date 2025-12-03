# Changelog

All notable changes to WinProc MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-03

### Added
- Initial release of WinProc MCP
- Claude Code MCP server integration
- Standalone PowerShell CLI interface (`winproc-cli.ps1`)
- Comprehensive process and service management
- UAC elevation for administrative operations
- Multiple process analysis functionality
- Port range support (e.g., `3000-3005`)
- Process chain visualization with parent/child relationships
- Network connection analysis (listening ports + active connections)
- Service discovery with wildcard support
- Automatic setup script (`winproc_mcp_setup.py`)

### Features
- **Discovery Tools**: Find processes by service, port, or PID
- **Management Tools**: Kill processes, manage services with UAC elevation
- **Multi-Process Analysis**: Analyze multiple PIDs simultaneously
- **Security**: Confirmation prompts for destructive operations
- **CLI Interface**: Direct command-line access without Claude Code
- **Comprehensive Output**: Memory usage, process trees, network connections

### Security
- UAC elevation only when required for administrative operations
- Confirmation prompts for all destructive operations
- Safe defaults with read-only operations requiring no elevation
- Process tree analysis to show impact before operations

### Technical
- Python 3.8+ support
- PowerShell 5.1+ compatibility
- Windows 10/11 and Windows Server support
- MCP (Model Context Protocol) integration
- PSScriptAnalyzer compliant PowerShell functions