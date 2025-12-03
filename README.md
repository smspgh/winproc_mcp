# WinProc MCP

[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/en-us/windows)

## Overview
**WinProc MCP** is a comprehensive Windows process and service management tool that provides both AI-assisted and direct command-line interfaces. It enables secure discovery, inspection, and control of any Windows service or process by name, PID, or port number with integrated UAC elevation.

### 🚀 **Dual Interface Design**
- **🤖 Claude Code Integration**: Full MCP server for AI-assisted process management
- **⚡ Standalone CLI**: Direct PowerShell interface via `winproc-cli.ps1`
- **🔒 Unified Security**: Consistent UAC elevation across both interfaces

## Key Features

### 🔍 **Discovery & Inspection**
- Find processes by name pattern (wildcards like `node*`, `*chrome*`)
- Find processes by service name (supports wildcards)
- Find processes listening on specific ports or port ranges
- Get detailed process information by single or multiple PIDs
- List all listening ports on the system
- Analyze complete process trees with parent/child relationships
- Network connection analysis (listening ports + active connections)
- Process chain visualization with memory and resource usage

### 🛠️ **Management Capabilities**
- Kill individual processes by PID
- Kill multiple processes at once
- Kill all processes using specific ports
- Start, stop, and restart Windows services
- UAC elevation for admin operations (no need to run Claude Code as admin)

### 🔒 **Security Features**
- **UAC Elevation**: Only prompts for admin privileges when needed
- **Confirmation Required**: All destructive operations require explicit confirmation
- **Safe Defaults**: Read-only operations work without elevation
- **Process Tree Analysis**: Shows impact before performing operations
- **Dry Run Mode**: Preview what operations would do without making changes
- **Audit Logging**: All operations are logged to `winproc_audit.log`

## Installation

### Prerequisites
- **Windows OS** (Windows 10/11 or Windows Server)
- **Python 3.8+**
- **PowerShell 7.x** (recommended) - [Install PowerShell 7](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)
  - Windows PowerShell 5.1 may work but has known parsing limitations
- **Claude Code** installed

### Quick Setup (Recommended)

**Option A: Automatic Setup**
```powershell
# Install dependencies and configure automatically
pip install -r requirements.txt
python winproc_mcp_setup.py
```

The setup script will:
- ✅ Check dependencies and PowerShell policy
- ✅ Automatically add MCP server to your Claude config
- ✅ Create backup of existing config
- ✅ Show next steps

**Option B: Manual Setup**

### 1. Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Configure PowerShell Execution Policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Add to Claude Code Settings
Add this configuration to your Claude Code settings file (`%USERPROFILE%\.claude.json`):

```json
{
  "mcpServers": {
    "winproc_mcp": {
      "type": "stdio",
      "command": "python",
      "args": [
        "C:\\path\\to\\your\\winproc_mcp\\winproc_mcp.py"
      ],
      "env": {}
    }
  }
}
```

**Replace the path** with your actual installation directory.

### 4. Restart Claude Code
Close and restart Claude Code to load the new MCP server.

## Standalone CLI Usage

For direct command-line access without Claude Code, use the included `winproc-cli.ps1` script:

### 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```powershell
# Clone and setup in one go
git clone https://github.com/smspgh/winproc_mcp winproc_mcp
cd winproc_mcp
pip install -r requirements.txt
python winproc_mcp_setup.py
```

### Option 2: Quick CLI Examples
```powershell
# Check what's running on development ports
.\winproc-cli.ps1 check-ports 3000-3005

# Check specific ports
.\winproc-cli.ps1 check-ports 443,8080,8443

# Find services with wildcards (shows full details including ports)
.\winproc-cli.ps1 find-service "*Docker*"

# Get detailed process info with full chain analysis
.\winproc-cli.ps1 process-info 1234

# Get process info with metric definitions explained
.\winproc-cli.ps1 process-info 1234 -d

# Learn what memory metrics mean
.\winproc-cli.ps1 definitions memory

# Kill processes on specific ports (requires admin)
.\winproc-cli.ps1 kill-port 8080 -Force

# Show all available commands
.\winproc-cli.ps1 help
```

### 📋 CLI Commands Reference
| Command | Description | Admin Required | Example |
|---------|-------------|----------------|---------|
| `check-ports <ports>` | Check what's listening on ports | ❌ | `check-ports 3000-3005` |
| `all-ports` | Show all listening ports | ❌ | `all-ports` |
| `find-service <pattern>` | Find services with full details | ❌ | `find-service "*Docker*"` |
| `service-info <name>` | Get service details | ❌ | `service-info "W3SVC"` |
| `process-info <PID>` | Comprehensive process analysis | ❌ | `process-info 1234` |
| `definitions [category]` | Show metric definitions | ❌ | `definitions memory` |
| `kill-process <PID>` | Terminate specific process | ✅ | `kill-process 1234` |
| `kill-port <ports>` | Kill processes using ports | ✅ | `kill-port 8080 -Force` |
| `kill-multiple <PIDs>` | Kill multiple processes | ✅ | `kill-multiple 1234,5678` |
| `stop-service <name>` | Stop Windows service | ✅ | `stop-service "Docker"` |
| `start-service <name>` | Start Windows service | ✅ | `start-service "W3SVC"` |
| `restart-service <name>` | Restart Windows service | ✅ | `restart-service "IIS"` |

### 🏷️ CLI Options
| Option | Description | Example |
|--------|-------------|---------|
| `-Force` | Skip confirmation prompts | `kill-port 8080 -Force` |
| `-Definitions` (`-d`) | Show metric definitions with output | `process-info 1234 -d` |

### 📖 Definitions Categories
Use `.\winproc-cli.ps1 definitions [category]` to learn what each metric means:
| Category | Description |
|----------|-------------|
| `process` | Process name, PID, memory, CPU time, priority, etc. |
| `chain` | Parent/child process relationships |
| `network` | Listening ports, connections, addresses |
| `modules` | Loaded DLLs and their memory usage |
| `memory` | Working set, virtual memory, private memory |
| `service` | Service name, status, start type |
| `all` | Show all categories (default) |

### 🔍 Enhanced find-service Output
The `find-service` command now shows comprehensive details for each matching service:
```
Finding services matching: *mongo*

Found 1 service(s) matching '*mongo*'

=== MongoDB ===
Display Name: MongoDB Server (MongoDB)
Status: Running
Start Type: Automatic
Executable: "C:\Program Files\MongoDB\Server\8.2\bin\mongod.exe" --config "C:\Program Files\MongoDB\Server\8.2\bin\mongod.cfg" --service
Run As: NT AUTHORITY\NetworkService
Description: MongoDB Database Server (MongoDB)
Listening Ports:
  └─ Port 27017 [127.0.0.1]
```

## Claude Code Usage Examples

### Service Management
```
"Find processes for services matching SQL*"
"Find processes for WindowsTestService" 
"Find processes for *Web*"
"Stop service W3SVC"
"Start service MSSQLSERVER"
"Restart service Docker Desktop Service"
```

### Port-Based Discovery
```
"What process is listening on port 80?"
"Find processes on ports 443, 8080, and 3000"
"Kill all processes using port 8080"
```

### Process Management
```
"Get detailed information about process 1234"
"Get information about multiple processes 1234, 5678, 9012"
"Kill process 5678"
"Kill processes 1234, 5678, 9012"
"Show me all listening ports"
```

### Multiple Process Analysis
```
"Analyze processes 51008 and 30200 together"
"Compare resource usage for PIDs 1234, 5678, 9012"
"Show network connections for processes 51008, 30200"
"Get detailed chain info for multiple Node.js processes"
```

### Advanced Operations
```
"Find all IIS-related services and their ports"
"Stop all Node.js processes on development ports"
"Find which service is using port 443 and restart it"
```

## Available MCP Tools

### Discovery Tools (No Admin Required)
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `find_processes_by_name` | Find processes by name pattern | `"Find node* processes"` |
| `find_processes_by_service` | Find processes for any service pattern | `"Find *SQL* services"` |
| `find_processes_by_port` | Find processes on specific ports | `"What's on port 80?"` |
| `get_all_listening_ports` | List all listening ports | `"Show all ports"` |
| `get_process_info` | Get details for a PID | `"Info for process 1234"` |
| `get_multiple_process_info` | Get details for multiple PIDs | `"Info for processes [1234, 5678]"` |
| `get_service_info` | Get details for a service | `"Info for W3SVC service"` |

### Management Tools (UAC Elevation Required)
| Tool | Description | Options |
|------|-------------|---------|
| `kill_process` | Terminate a process by PID | `force`, `dry_run` |
| `kill_processes_by_port` | Kill all processes on port(s) | `force`, `dry_run` |
| `kill_multiple_processes` | Kill multiple processes by PIDs | `force`, `dry_run` |
| `stop_service` | Stop a Windows service | `force`, `dry_run` |
| `start_service` | Start a Windows service | `dry_run` |
| `restart_service` | Restart a Windows service | `force`, `dry_run` |

### Dry Run Mode
All destructive operations support a `dry_run` parameter that shows what would happen without making changes:
```
"Kill process 1234 with dry_run"
"Stop service Docker with dry_run=true"
```

## File Structure

```
winproc_mcp/
├── winproc_mcp.py           # Main MCP server with UAC elevation
├── winproc-cli.ps1          # Standalone CLI interface
├── admin_helper.ps1         # PowerShell helper for elevated operations
├── winproc_mcp_setup.py     # Automatic setup script
├── requirements.txt         # Python dependencies
├── pytest.ini               # Test configuration
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures
│   └── test_winproc_mcp.py  # Unit tests
├── winproc_audit.log        # Audit log (created on first operation)
├── CHANGELOG.md             # Version history
└── README.md                # This documentation
```

## How UAC Elevation Works

1. **Normal Operations**: Claude Code runs with standard user privileges
2. **Admin Required**: When you request a destructive operation (kill process, stop service)
3. **UAC Prompt**: Windows shows a UAC dialog asking for administrator approval
4. **Elevated Execution**: If approved, the operation runs with admin privileges in a separate session
5. **Return to Normal**: After completion, returns to standard privileges

This approach is **more secure** than running Claude Code as administrator constantly.

## Troubleshooting

**"Administrator privileges required"**
- This is normal for kill/service operations
- Approve the UAC prompt when it appears
- If UAC is disabled, you could run Claude Code as Administrator but I would advise to NOT do this.

**"PowerShell execution policy error"**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Module not found" errors**
```powershell
pip install mcp pydantic
```

**"Service not found"**
- Use wildcards: `*partial-name*`
- Check exact service name: `Get-Service` in PowerShell

**"Process not found"**
- Process may have already terminated
- Check PID with Task Manager or `Get-Process`

### Getting Service Names
To find the exact names of Windows services:
```powershell
Get-Service | Where-Object {$_.DisplayName -like "*keyword*"}
```

### Checking Port Usage
To see what's using ports:
```powershell
netstat -ano | findstr :PORT_NUMBER
```

## Security Considerations

### Safe Operations
- **Read operations** never require elevation
- **Discovery tools** are completely safe
- **UAC prompts** appear only for destructive operations

### Admin Operations
- **Always confirm** before approving UAC prompts
- **Review the operation** in the confirmation dialog
- **Cancel** if you're unsure about the operation

### Best Practices
- Use **discovery tools first** to understand what you're managing
- **Review process trees** before killing multiple processes
- **Prefer service operations** over direct process killing when possible
- **Test on non-critical systems** first

## Example Workflows

### Troubleshooting a Web Service
1. `"Find processes for *Web*"` - Discover web-related services
2. `"What's listening on port 80?"` - Check if port is in use
3. `"Get info for service W3SVC"` - Get IIS service details
4. `"Restart service W3SVC"` - Restart if needed

### Cleaning Up Development Processes
1. `"Find processes on ports 3000, 8080, 9000"` - Find dev servers
2. `"Kill processes using ports 3000, 8080"` - Clean up dev ports
3. `"Show all listening ports"` - Verify cleanup

**CLI Alternative:**
```powershell
.\winproc-cli.ps1 check-ports 3000-9000
.\winproc-cli.ps1 kill-port 3000,8080 -Force
.\winproc-cli.ps1 all-ports
```

### Managing Database Services
1. `"Find services matching *SQL*"` - Find database services
2. `"Stop service MSSQLSERVER"` - Stop SQL Server
3. `"Start service MSSQLSERVER"` - Start SQL Server

### Analyzing Multiple Processes (NEW)
Comprehensive analysis of multiple processes at once:

**Claude Code Examples:**
```
"Analyze processes 51008 and 30200 together"
"Compare memory usage for Node.js processes 1234, 5678"
"Show network connections for multiple processes [51008, 30200]"
```

**CLI Example:**
```powershell
# Get detailed info on multiple processes
.\winproc-cli.ps1 process-info 51008  # Individual analysis
.\winproc-cli.ps1 process-info 30200  # Individual analysis
```

**What Multiple Process Analysis Shows:**
- **Individual Details**: Complete process info for each PID
- **Parent/Child Relationships**: Process tree visualization
- **Network Analysis**: Listening ports + active connections per process
- **Resource Summary**: Combined memory usage and process type grouping
- **Process Chain**: How processes relate to each other
- **Service Associations**: Which processes belong to services

**Example Output Summary:**
```
Found: 2 of 2 processes
Total Memory: 113.7 MB
Process Types:
  node: 2 instances
```

## 🔧 Advanced Configuration

### PowerShell Execution Policy
If you encounter execution policy errors:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Custom Port Ranges
The CLI supports flexible port specifications:
```powershell
# Single ports
.\winproc-cli.ps1 check-ports 80

# Multiple ports
.\winproc-cli.ps1 check-ports 80,443,8080

# Port ranges
.\winproc-cli.ps1 check-ports 3000-3010

# Mixed notation
.\winproc-cli.ps1 check-ports 80,443,3000-3005,8080
```

### Environment Variables
Set these for customized behavior:
| Variable | Default | Description |
|----------|---------|-------------|
| `WINPROC_TIMEOUT` | `30` | Timeout for standard operations (seconds) |
| `WINPROC_ELEVATED_TIMEOUT` | `60` | Timeout for UAC-elevated operations (seconds) |
| `WINPROC_AUDIT_LOG` | `winproc_audit.log` | Path to audit log file |
| `WINPROC_AUDIT_ENABLED` | `true` | Enable/disable audit logging |

Example configuration in Claude config:
```json
{
  "mcpServers": {
    "winproc_mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\path\\to\\winproc_mcp.py"],
      "env": {
        "WINPROC_TIMEOUT": "45",
        "WINPROC_AUDIT_ENABLED": "true"
      }
    }
  }
}
```

## 🤝 Contributing

WinProc MCP is designed with these principles:
- **🛡️ Security First** - UAC elevation only when needed
- **🔧 Extensible** - Easy to add new commands and features  
- **🎯 User-Friendly** - Clear confirmations and error messages
- **📊 Comprehensive** - Complete process and service lifecycle management

### Development Setup
```powershell
git clone <repository-url>
cd winproc_mcp
pip install -r requirements.txt

# Run tests
pytest

# Run tests with verbose output
pytest -v

# Test CLI
.\winproc-cli.ps1 help

# Test MCP server
python winproc_mcp.py
```

## 📄 License

This project is provided as-is under the MIT License for managing Windows processes and services.

## 🙏 Acknowledgments

- Built for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) MCP integration
- Powered by Windows PowerShell and Python
- Designed for Windows system administrators and developers
