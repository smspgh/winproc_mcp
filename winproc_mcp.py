#!/usr/bin/env python3
"""
WinProc MCP - Windows Process and Service Management with UAC Elevation
Handles any Windows service or process by PID, service name, or port
"""

import asyncio
import subprocess
import sys
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, List

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configuration from environment variables
WINPROC_TIMEOUT = int(os.environ.get("WINPROC_TIMEOUT", "30"))
WINPROC_ELEVATED_TIMEOUT = int(os.environ.get("WINPROC_ELEVATED_TIMEOUT", "60"))
WINPROC_AUDIT_LOG = os.environ.get("WINPROC_AUDIT_LOG", os.path.join(os.path.dirname(__file__), "winproc_audit.log"))
WINPROC_AUDIT_ENABLED = os.environ.get("WINPROC_AUDIT_ENABLED", "true").lower() == "true"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("winproc-mcp")

# Audit logger - separate file for operation tracking
audit_logger = logging.getLogger("winproc-audit")
audit_logger.setLevel(logging.INFO)
if WINPROC_AUDIT_ENABLED:
    audit_handler = RotatingFileHandler(
        WINPROC_AUDIT_LOG,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3
    )
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    audit_logger.addHandler(audit_handler)


def audit_log(operation: str, target: str, result: str, details: str = ""):
    """Log an operation to the audit log"""
    if WINPROC_AUDIT_ENABLED:
        message = f"OPERATION={operation} | TARGET={target} | RESULT={result}"
        if details:
            message += f" | DETAILS={details}"
        audit_logger.info(message)

# Server
server = Server("winproc-mcp")

def run_powershell(script: str, timeout: int = None) -> str:
    """Run PowerShell and return output"""
    if timeout is None:
        timeout = WINPROC_TIMEOUT
    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error: {str(e)}"

def run_elevated_operation(operation: str, target: str, force: bool = False, dry_run: bool = False) -> str:
    """Run an operation with UAC elevation using the admin helper script"""
    # Audit log the attempt
    audit_log(operation, target, "ATTEMPTED", f"force={force}, dry_run={dry_run}")

    if dry_run:
        audit_log(operation, target, "DRY_RUN", "Operation simulated, no changes made")
        return f"[DRY RUN] Would execute: {operation} on target: {target} (force={force})"

    try:
        # Path to the admin helper script
        script_path = os.path.join(os.path.dirname(__file__), "admin_helper.ps1")

        # Build the command
        force_arg = " -Force" if force else ""
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"{script_path}\" -Operation {operation} -Target \"{target}\"{force_arg}' -Verb RunAs -Wait"
        ]

        # Execute with UAC prompt
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=WINPROC_ELEVATED_TIMEOUT
        )

        if result.returncode == 0:
            audit_log(operation, target, "SUCCESS", "UAC elevation completed")
            return "Operation completed successfully (UAC elevation was used)"
        else:
            audit_log(operation, target, "FAILED", f"User cancelled or error: {result.stderr}")
            return f"Operation failed or was cancelled by user: {result.stderr}"

    except subprocess.TimeoutExpired:
        audit_log(operation, target, "TIMEOUT", f"Timed out after {WINPROC_ELEVATED_TIMEOUT}s")
        return f"Error: Operation timed out after {WINPROC_ELEVATED_TIMEOUT} seconds"
    except Exception as e:
        audit_log(operation, target, "ERROR", str(e))
        return f"Error during elevated operation: {str(e)}"

def check_admin_privileges() -> bool:
    """Check if currently running with administrator privileges"""
    script = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    result = run_powershell(script)
    return result.strip().lower() == "true"

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="find_processes_by_name",
            description="Find processes by name pattern (supports wildcards like 'node*' or '*chrome*')",
            inputSchema={
                "type": "object",
                "properties": {
                    "name_pattern": {
                        "type": "string",
                        "description": "Process name pattern (supports wildcards like 'node*', '*python*', 'chrome')"
                    }
                },
                "required": ["name_pattern"]
            }
        ),
        Tool(
            name="find_processes_by_service",
            description="Find processes for any Windows service by name (supports wildcards)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_pattern": {
                        "type": "string",
                        "description": "Service name pattern (supports wildcards like 'SQL*' or '*Web*')"
                    }
                },
                "required": ["service_pattern"]
            }
        ),
        Tool(
            name="find_processes_by_port",
            description="Find processes listening on specific port(s)",
            inputSchema={
                "type": "object",
                "properties": {
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of port numbers to search for"
                    }
                },
                "required": ["ports"]
            }
        ),
        Tool(
            name="get_all_listening_ports",
            description="Get all listening ports on the system",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_process_info",
            description="Get detailed information about a process by PID",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_id": {
                        "type": "integer",
                        "description": "Process ID to get information for"
                    }
                },
                "required": ["process_id"]
            }
        ),
        Tool(
            name="get_multiple_process_info",
            description="Get detailed information about multiple processes by PID list",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of process IDs to get information for"
                    }
                },
                "required": ["process_ids"]
            }
        ),
        Tool(
            name="get_service_info",
            description="Get detailed information about a Windows service",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Service name (exact name or pattern with wildcards)"
                    }
                },
                "required": ["service_name"]
            }
        ),
        Tool(
            name="kill_process",
            description="Terminate a specific process by PID (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_id": {
                        "type": "integer",
                        "description": "Process ID to terminate"
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip confirmation prompt in elevated session"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["process_id"]
            }
        ),
        Tool(
            name="kill_processes_by_port",
            description="Kill all processes listening on specific port(s) (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of port numbers - will kill all processes using these ports"
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip confirmation prompt in elevated session"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["ports"]
            }
        ),
        Tool(
            name="kill_multiple_processes",
            description="Kill multiple processes by their PIDs (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of process IDs to terminate"
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip confirmation prompt in elevated session"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["process_ids"]
            }
        ),
        Tool(
            name="stop_service",
            description="Stop any Windows service by name (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Service name to stop"
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip confirmation prompt in elevated session"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["service_name"]
            }
        ),
        Tool(
            name="start_service",
            description="Start any Windows service by name (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Service name to start"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["service_name"]
            }
        ),
        Tool(
            name="restart_service",
            description="Restart any Windows service by name (will prompt for UAC elevation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Service name to restart"
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Skip confirmation prompt in elevated session"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "default": False,
                        "description": "Preview what would be done without making changes"
                    }
                },
                "required": ["service_name"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any] | None) -> List[TextContent]:
    """Handle tool calls"""
    if arguments is None:
        arguments = {}
    
    # Read-only operations (no elevation needed)
    if name == "find_processes_by_name":
        name_pattern = arguments.get("name_pattern", "")
        if not name_pattern:
            return [TextContent(type="text", text="Error: No process name pattern specified")]

        audit_log("find_processes_by_name", name_pattern, "EXECUTED")

        script = f"""
        Write-Host "=== Process Search: {name_pattern} ==="
        $processes = Get-Process | Where-Object {{ $_.ProcessName -like "{name_pattern}" }}

        if ($processes) {{
            $totalMemory = 0
            $processCount = @($processes).Count
            Write-Host "Found $processCount process(es) matching '{name_pattern}'"
            Write-Host ""

            foreach ($proc in $processes) {{
                Write-Host "--- $($proc.ProcessName) (PID: $($proc.Id)) ---" -ForegroundColor Cyan
                $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
                $totalMemory += $proc.WorkingSet64
                Write-Host "  Memory: $memMB MB"

                # Get command line via WMI
                $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                if ($wmiProc -and $wmiProc.CommandLine) {{
                    $cmdLine = $wmiProc.CommandLine
                    if ($cmdLine.Length -gt 100) {{ $cmdLine = $cmdLine.Substring(0, 100) + "..." }}
                    Write-Host "  Command: $cmdLine"
                }}

                # Check for listening ports
                $tcpPorts = Get-NetTCPConnection -OwningProcess $proc.Id -State Listen -ErrorAction SilentlyContinue
                if ($tcpPorts) {{
                    $portList = ($tcpPorts | ForEach-Object {{ $_.LocalPort }}) -join ', '
                    Write-Host "  Listening Ports: $portList"
                }}

                # Parent process
                if ($wmiProc -and $wmiProc.ParentProcessId) {{
                    $parent = Get-Process -Id $wmiProc.ParentProcessId -ErrorAction SilentlyContinue
                    if ($parent) {{
                        Write-Host "  Parent: $($parent.ProcessName) (PID: $($wmiProc.ParentProcessId))"
                    }}
                }}
                Write-Host ""
            }}

            Write-Host "=== Summary ==="
            Write-Host "Total Processes: $processCount"
            Write-Host "Total Memory: $([math]::Round($totalMemory / 1MB, 1)) MB"
            $pids = ($processes | ForEach-Object {{ $_.Id }}) -join ', '
            Write-Host "Process IDs: $pids"
            Write-Host ""
            Write-Host "Use 'kill_multiple_processes' with these PIDs to terminate all matching processes"
        }} else {{
            Write-Host "No processes found matching pattern: {name_pattern}"
        }}
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]

    elif name == "find_processes_by_service":
        service_pattern = arguments.get("service_pattern", "")
        if not service_pattern:
            return [TextContent(type="text", text="Error: No service pattern specified")]
        
        script = f"""
        Write-Host "=== Service Search: {service_pattern} ==="
        $services = Get-Service | Where-Object {{ $_.Name -like "{service_pattern}" -or $_.DisplayName -like "*{service_pattern}*" }}
        
        if ($services) {{
            foreach ($service in $services) {{
                Write-Host ""
                Write-Host "Service: $($service.Name) - $($service.DisplayName)"
                Write-Host "Status: $($service.Status)"
                Write-Host "Start Type: $($service.StartType)"
                
                if ($service.Status -eq "Running") {{
                    $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'"
                    $processId = $wmiService.ProcessId
                    
                    if ($processId -gt 0) {{
                        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                        if ($process) {{
                            Write-Host "Main Process: $($process.ProcessName) (PID: $processId)"
                            Write-Host "Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 1)) MB"
                            
                            # Get all related processes (process tree)
                            $allProcesses = @($processId)
                            
                            function Get-AllChildren($parentPid) {{
                                $children = Get-WmiObject Win32_Process -Filter "ParentProcessId=$parentPid" -ErrorAction SilentlyContinue
                                foreach ($child in $children) {{
                                    $script:allProcesses += $child.ProcessId
                                    Get-AllChildren $child.ProcessId
                                }}
                            }}
                            
                            Get-AllChildren $processId
                            
                            if ($allProcesses.Count -gt 1) {{
                                Write-Host "Process Tree:"
                                foreach ($processIdVar in $allProcesses) {{
                                    $proc = Get-Process -Id $processIdVar -ErrorAction SilentlyContinue
                                    if ($proc) {{
                                        Write-Host "  $($proc.ProcessName) (PID: $processIdVar)"
                                        
                                        # Check for ports
                                        $tcpPorts = Get-NetTCPConnection -OwningProcess $processIdVar -State Listen -ErrorAction SilentlyContinue
                                        if ($tcpPorts) {{
                                            Write-Host "    TCP Ports:"
                                            $tcpPorts | ForEach-Object {{ Write-Host "      $($_.LocalAddress):$($_.LocalPort)" }}
                                        }}
                                    }}
                                }}
                                
                                Write-Host ""
                                Write-Host "=== Management Options ==="
                                Write-Host "All Process IDs: $($allProcesses -join ', ')"
                                Write-Host "Use 'kill_multiple_processes' with these PIDs to terminate the entire tree"
                                Write-Host "Use 'stop_service' with service name '$($service.Name)' to stop the service"
                            }} else {{
                                $tcpPorts = Get-NetTCPConnection -OwningProcess $processId -State Listen -ErrorAction SilentlyContinue
                                if ($tcpPorts) {{
                                    Write-Host "TCP Ports:"
                                    $tcpPorts | ForEach-Object {{ Write-Host "  $($_.LocalAddress):$($_.LocalPort)" }}
                                }}
                            }}
                        }}
                    }}
                }} else {{
                    Write-Host "Service is not running"
                }}
            }}
        }} else {{
            Write-Host "No services found matching pattern: {service_pattern}"
        }}
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]
    
    elif name == "get_service_info":
        service_name = arguments.get("service_name", "")
        if not service_name:
            return [TextContent(type="text", text="Error: No service name specified")]
        
        # Use the same logic as find_processes_by_service but for a specific service
        return await call_tool("find_processes_by_service", {"service_pattern": service_name})
    
    elif name == "find_processes_by_port":
        ports = arguments.get("ports", [])
        if not ports:
            return [TextContent(type="text", text="Error: No ports specified")]
        
        port_list = ",".join(map(str, ports))
        script = f"""
        Write-Host "=== Port Search: {port_list} ==="
        $foundProcesses = @()
        
        foreach ($port in @({port_list})) {{
            $tcpResult = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
            
            if ($tcpResult) {{
                Write-Host ""
                Write-Host "Port $port (TCP):"
                $tcpResult | ForEach-Object {{
                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) {{
                        Write-Host "  Process: $($proc.ProcessName) (PID: $($_.OwningProcess))"
                        Write-Host "  Address: $($_.LocalAddress):$($_.LocalPort)"
                        $foundProcesses += $_.OwningProcess
                        
                        # Try to find parent service
                        $currentPid = $_.OwningProcess
                        for ($i = 0; $i -lt 5; $i++) {{
                            $service = Get-WmiObject Win32_Service | Where-Object {{ $_.ProcessId -eq $currentPid }}
                            if ($service) {{
                                Write-Host "  Parent Service: $($service.Name) - $($service.DisplayName)"
                                break
                            }}
                            $parentProc = Get-WmiObject Win32_Process -Filter "ProcessId=$currentPid"
                            if ($parentProc -and $parentProc.ParentProcessId) {{
                                $currentPid = $parentProc.ParentProcessId
                            }} else {{
                                break
                            }}
                        }}
                    }}
                }}
            }}
        }}
        
        if ($foundProcesses.Count -eq 0) {{
            Write-Host "No processes found listening on ports: {port_list}"
        }} else {{
            $uniqueProcesses = $foundProcesses | Sort-Object -Unique
            Write-Host ""
            Write-Host "=== Management Options ==="
            Write-Host "Found $($uniqueProcesses.Count) unique process(es) using the specified ports"
            Write-Host "Process IDs: $($uniqueProcesses -join ', ')"
            Write-Host "Use 'kill_processes_by_port' to terminate all processes using these ports"
            Write-Host "Use 'kill_multiple_processes' to terminate specific PIDs"
        }}
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]
    
    elif name == "get_all_listening_ports":
        script = """
        Write-Host "=== All Listening TCP Ports ==="
        $tcpPorts = Get-NetTCPConnection -State Listen | Sort-Object LocalPort
        
        foreach ($port in $tcpPorts) {
            $proc = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "Port $($port.LocalPort): $($proc.ProcessName) (PID: $($port.OwningProcess))"
            }
        }
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]
    
    elif name == "get_process_info":
        process_id = arguments.get("process_id", 0)
        if process_id <= 0:
            return [TextContent(type="text", text="Error: Invalid process ID")]
        
        script = f"""
        $process = Get-Process -Id {process_id} -ErrorAction SilentlyContinue
        if ($process) {{
            Write-Host "=== Process Information for PID {process_id} ==="
            Write-Host "Process Name: $($process.ProcessName)"
            Write-Host "Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 1)) MB"
            
            $wmiProcess = Get-WmiObject Win32_Process -Filter "ProcessId={process_id}"
            if ($wmiProcess -and $wmiProcess.CommandLine) {{
                Write-Host "Command Line: $($wmiProcess.CommandLine)"
            }}
            
            # Check for listening ports
            $tcpPorts = Get-NetTCPConnection -OwningProcess {process_id} -State Listen -ErrorAction SilentlyContinue
            if ($tcpPorts) {{
                Write-Host "TCP Listening Ports:"
                $tcpPorts | ForEach-Object {{ Write-Host "  $($_.LocalAddress):$($_.LocalPort)" }}
            }}
            
            # Check for parent service
            $service = Get-WmiObject Win32_Service | Where-Object {{ $_.ProcessId -eq {process_id} }}
            if ($service) {{
                Write-Host "Direct Service: $($service.Name) - $($service.DisplayName)"
            }}
            
            # Check for child processes
            $children = Get-WmiObject Win32_Process -Filter "ParentProcessId={process_id}" -ErrorAction SilentlyContinue
            if ($children) {{
                Write-Host "Child Processes:"
                foreach ($child in $children) {{
                    $childProc = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                    if ($childProc) {{
                        Write-Host "  $($childProc.ProcessName) (PID: $($child.ProcessId))"
                    }}
                }}
            }}
        }} else {{
            Write-Host "Process with PID {process_id} not found"
        }}
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]
    
    elif name == "get_multiple_process_info":
        process_ids = arguments.get("process_ids", [])
        if not process_ids or len(process_ids) == 0:
            return [TextContent(type="text", text="Error: No process IDs provided")]
        
        # Full detailed version using the working individual approach
        script = f"""
        Write-Host "=== Multiple Process Information ==="
        Write-Host "Analyzing {len(process_ids)} processes..."
        Write-Host ""
        """
        
        # Add each process individually with full details
        for i, pid in enumerate(process_ids):
            script += f"""
        Write-Host "=== Process Information for PID {pid} ==="
        $process{i} = Get-Process -Id {pid} -ErrorAction SilentlyContinue
        if ($process{i}) {{
            Write-Host "Process Name: $($process{i}.ProcessName)"
            Write-Host "Memory Usage: $([math]::Round($process{i}.WorkingSet64 / 1MB, 1)) MB"
            
            # Format CPU Time and Start Time
            if ($process{i}.TotalProcessorTime) {{
                Write-Host "CPU Time: $($process{i}.TotalProcessorTime)"
            }} else {{
                Write-Host "CPU Time: Not available"
            }}
            
            if ($process{i}.StartTime) {{
                Write-Host "Start Time: $($process{i}.StartTime)"
            }} else {{
                Write-Host "Start Time: Not available"
            }}
            
            Write-Host "Priority: $($process{i}.BasePriority)"
            Write-Host "Thread Count: $($process{i}.Threads.Count)"
            
            # Get WMI info for command line and parent
            $wmiProcess{i} = Get-WmiObject Win32_Process -Filter "ProcessId={pid}" -ErrorAction SilentlyContinue
            if ($wmiProcess{i}) {{
                if ($wmiProcess{i}.CommandLine) {{
                    Write-Host "Command Line: $($wmiProcess{i}.CommandLine)"
                }} else {{
                    Write-Host "Command Line: Not available"
                }}
                
                if ($wmiProcess{i}.ExecutablePath) {{
                    Write-Host "Executable Path: $($wmiProcess{i}.ExecutablePath)"
                }} else {{
                    Write-Host "Executable Path: Not available"
                }}
                
                # Parent process
                if ($wmiProcess{i}.ParentProcessId) {{
                    $parentProc{i} = Get-Process -Id $wmiProcess{i}.ParentProcessId -ErrorAction SilentlyContinue
                    if ($parentProc{i}) {{
                        Write-Host "Parent Process: $($parentProc{i}.ProcessName) (PID: $($wmiProcess{i}.ParentProcessId))"
                    }} else {{
                        Write-Host "Parent Process: (PID: $($wmiProcess{i}.ParentProcessId)) - Process no longer exists"
                    }}
                }} else {{
                    Write-Host "Parent Process: Not available"
                }}
            }}
            
            # Check for listening ports
            $tcpPorts{i} = Get-NetTCPConnection -OwningProcess {pid} -State Listen -ErrorAction SilentlyContinue
            if ($tcpPorts{i}) {{
                Write-Host "TCP Listening Ports:"
                $tcpPorts{i} | ForEach-Object {{ Write-Host "  $($_.LocalAddress):$($_.LocalPort)" }}
            }}
            
            # Check for active connections
            $activePorts{i} = Get-NetTCPConnection -OwningProcess {pid} -ErrorAction SilentlyContinue | Where-Object {{ $_.State -ne "Listen" }}
            if ($activePorts{i}) {{
                Write-Host "Active Connections:"
                $activePorts{i} | Select-Object -First 5 | ForEach-Object {{ 
                    Write-Host "  $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]" 
                }}
                if ($activePorts{i}.Count -gt 5) {{
                    Write-Host "  ... and $($activePorts{i}.Count - 5) more connections"
                }}
            }}
            
            # Check for child processes
            $children{i} = Get-WmiObject Win32_Process -Filter "ParentProcessId={pid}" -ErrorAction SilentlyContinue
            if ($children{i}) {{
                Write-Host "Child Processes:"
                foreach ($child in $children{i}) {{
                    $childProc = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                    if ($childProc) {{
                        Write-Host "  $($childProc.ProcessName) (PID: $($child.ProcessId))"
                    }}
                }}
            }}
            
            # Check for direct service
            $service{i} = Get-WmiObject Win32_Service | Where-Object {{ $_.ProcessId -eq {pid} }}
            if ($service{i}) {{
                Write-Host "Direct Service: $($service{i}.Name) - $($service{i}.DisplayName)"
            }}
            
            Write-Host ""
        }} else {{
            Write-Host "Process with PID {pid} not found"
            Write-Host ""
        }}
        """
        
        # Add summary section
        script += f"""
        Write-Host "=== Summary ==="
        $totalMemory = 0
        $foundCount = 0
        $processNames = @()
        """
        
        for i, pid in enumerate(process_ids):
            script += f"""
        if ($process{i}) {{
            $totalMemory += $process{i}.WorkingSet64
            $foundCount++
            $processNames += $process{i}.ProcessName
        }}
        """
        
        script += f"""
        Write-Host "Found: $foundCount of {len(process_ids)} processes"
        if ($foundCount -gt 0) {{
            Write-Host "Total Memory: $([math]::Round($totalMemory / 1MB, 1)) MB"
            $grouped = $processNames | Group-Object
            Write-Host "Process Types:"
            foreach ($group in $grouped) {{
                Write-Host "  $($group.Name): $($group.Count) instances"
            }}
        }}
        """
        output = run_powershell(script)
        return [TextContent(type="text", text=output)]
    
    # Operations requiring elevation
    elif name == "kill_process":
        process_id = arguments.get("process_id", 0)
        force = arguments.get("force", False)
        dry_run = arguments.get("dry_run", False)

        if process_id <= 0:
            return [TextContent(type="text", text="Error: Invalid process ID")]

        # Dry run - show what would happen
        if dry_run:
            script = f"""
            $process = Get-Process -Id {process_id} -ErrorAction SilentlyContinue
            if ($process) {{
                Write-Host "[DRY RUN] Would terminate process:"
                Write-Host "  Name: $($process.ProcessName)"
                Write-Host "  PID: {process_id}"
                Write-Host "  Memory: $([math]::Round($process.WorkingSet64 / 1MB, 1)) MB"
                $tcpPorts = Get-NetTCPConnection -OwningProcess {process_id} -State Listen -ErrorAction SilentlyContinue
                if ($tcpPorts) {{
                    Write-Host "  Listening Ports: $(($tcpPorts | ForEach-Object {{ $_.LocalPort }}) -join ', ')"
                }}
                Write-Host ""
                Write-Host "No changes made (dry run mode)"
            }} else {{
                Write-Host "[DRY RUN] Process with PID {process_id} not found"
            }}
            """
            audit_log("kill_process", str(process_id), "DRY_RUN")
            output = run_powershell(script)
            return [TextContent(type="text", text=output)]

        if check_admin_privileges():
            # Run directly if already admin
            script = f"""
            try {{
                $process = Get-Process -Id {process_id} -ErrorAction SilentlyContinue
                if ($process) {{
                    Write-Host "Terminating process: $($process.ProcessName) (PID: {process_id})"
                    Stop-Process -Id {process_id} -Force
                    Write-Host "Process {process_id} terminated successfully"
                }} else {{
                    Write-Host "Process with PID {process_id} not found"
                }}
            }} catch {{
                Write-Host "Error terminating process {process_id}: $_"
            }}
            """
            audit_log("kill_process", str(process_id), "EXECUTED_AS_ADMIN")
            output = run_powershell(script)
        else:
            # Use UAC elevation
            output = run_elevated_operation("kill-process", str(process_id), force)

        return [TextContent(type="text", text=output)]
    
    elif name == "kill_processes_by_port":
        ports = arguments.get("ports", [])
        force = arguments.get("force", False)
        dry_run = arguments.get("dry_run", False)

        if not ports:
            return [TextContent(type="text", text="Error: No ports specified")]

        port_string = ",".join(map(str, ports))

        # Dry run - show what would happen
        if dry_run:
            script = f"""
            Write-Host "[DRY RUN] Would kill processes on ports: {port_string}"
            Write-Host ""
            $portsToCheck = @({port_string})
            $foundProcesses = @()

            foreach ($port in $portsToCheck) {{
                $tcpConnections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                if ($tcpConnections) {{
                    foreach ($conn in $tcpConnections) {{
                        $pid = $conn.OwningProcess
                        if ($pid -notin $foundProcesses) {{
                            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                            if ($proc) {{
                                Write-Host "Would terminate: $($proc.ProcessName) (PID: $pid) on port $port"
                                Write-Host "  Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 1)) MB"
                                $foundProcesses += $pid
                            }}
                        }}
                    }}
                }} else {{
                    Write-Host "No process found on port $port"
                }}
            }}

            Write-Host ""
            Write-Host "=== Summary ==="
            Write-Host "Would terminate $($foundProcesses.Count) process(es)"
            Write-Host "No changes made (dry run mode)"
            """
            audit_log("kill_processes_by_port", port_string, "DRY_RUN")
            output = run_powershell(script)
            return [TextContent(type="text", text=output)]

        if check_admin_privileges():
            # Run directly if already admin
            script = f"""
            $portsToKill = @({port_string})
            $killedProcesses = @()
            $errors = @()

            foreach ($port in $portsToKill) {{
                $tcpConnections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
                if ($tcpConnections) {{
                    foreach ($conn in $tcpConnections) {{
                        $pid = $conn.OwningProcess
                        if ($pid -notin $killedProcesses) {{
                            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                            if ($proc) {{
                                try {{
                                    Write-Host "Terminating process: $($proc.ProcessName) (PID: $pid) on port $port"
                                    Stop-Process -Id $pid -Force
                                    $killedProcesses += $pid
                                    Write-Host "Process $pid terminated successfully"
                                }} catch {{
                                    $errors += "Error terminating PID $pid`: $_"
                                }}
                            }}
                        }}
                    }}
                }} else {{
                    Write-Host "No process found listening on port $port"
                }}
            }}

            Write-Host ""
            Write-Host "=== Summary ==="
            Write-Host "Terminated $($killedProcesses.Count) process(es)"
            if ($errors.Count -gt 0) {{
                Write-Host "Errors:"
                $errors | ForEach-Object {{ Write-Host "  $_" }}
            }}
            """
            audit_log("kill_processes_by_port", port_string, "EXECUTED_AS_ADMIN")
            output = run_powershell(script)
        else:
            output = run_elevated_operation("kill-by-port", port_string, force)

        return [TextContent(type="text", text=output)]
    
    elif name == "kill_multiple_processes":
        process_ids = arguments.get("process_ids", [])
        force = arguments.get("force", False)
        dry_run = arguments.get("dry_run", False)

        if not process_ids:
            return [TextContent(type="text", text="Error: No process IDs specified")]

        pid_string = ",".join(map(str, process_ids))

        # Dry run - show what would happen
        if dry_run:
            script = f"""
            Write-Host "[DRY RUN] Would kill processes: {pid_string}"
            Write-Host ""
            $pidsToCheck = @({pid_string})
            $totalMemory = 0
            $foundCount = 0

            foreach ($pid in $pidsToCheck) {{
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {{
                    Write-Host "Would terminate: $($proc.ProcessName) (PID: $pid)"
                    Write-Host "  Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 1)) MB"
                    $totalMemory += $proc.WorkingSet64
                    $foundCount++
                }} else {{
                    Write-Host "PID $pid not found (already exited)"
                }}
            }}

            Write-Host ""
            Write-Host "=== Summary ==="
            Write-Host "Would terminate $foundCount of $($pidsToCheck.Count) process(es)"
            Write-Host "Total memory that would be freed: $([math]::Round($totalMemory / 1MB, 1)) MB"
            Write-Host "No changes made (dry run mode)"
            """
            audit_log("kill_multiple_processes", pid_string, "DRY_RUN")
            output = run_powershell(script)
            return [TextContent(type="text", text=output)]

        if check_admin_privileges():
            # Run directly if already admin
            script = f"""
            $pidsToKill = @({pid_string})
            $killedCount = 0
            $errors = @()

            foreach ($pid in $pidsToKill) {{
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {{
                    try {{
                        Write-Host "Terminating process: $($proc.ProcessName) (PID: $pid)"
                        Stop-Process -Id $pid -Force
                        $killedCount++
                        Write-Host "Process $pid terminated successfully"
                    }} catch {{
                        $errors += "Error terminating PID $pid`: $_"
                    }}
                }} else {{
                    Write-Host "Process with PID $pid not found (may have already exited)"
                }}
            }}

            Write-Host ""
            Write-Host "=== Summary ==="
            Write-Host "Terminated $killedCount of $($pidsToKill.Count) process(es)"
            if ($errors.Count -gt 0) {{
                Write-Host "Errors:"
                $errors | ForEach-Object {{ Write-Host "  $_" }}
            }}
            """
            audit_log("kill_multiple_processes", pid_string, "EXECUTED_AS_ADMIN")
            output = run_powershell(script)
        else:
            output = run_elevated_operation("kill-multiple", pid_string, force)

        return [TextContent(type="text", text=output)]
    
    elif name in ["stop_service", "start_service", "restart_service"]:
        service_name = arguments.get("service_name", "")
        force = arguments.get("force", False)
        dry_run = arguments.get("dry_run", False)

        if not service_name:
            return [TextContent(type="text", text="Error: No service name specified")]

        action = name.replace("_service", "").replace("_", "-")
        action_verb = action.replace("-", " ").title()

        # Dry run - show what would happen
        if dry_run:
            script = f"""
            $service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
            if ($service) {{
                Write-Host "[DRY RUN] Would {action_verb.lower()} service:"
                Write-Host "  Name: $($service.Name)"
                Write-Host "  Display Name: $($service.DisplayName)"
                Write-Host "  Current Status: $($service.Status)"
                Write-Host "  Start Type: $($service.StartType)"

                $wmiService = Get-WmiObject Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
                if ($wmiService -and $wmiService.ProcessId -gt 0) {{
                    $proc = Get-Process -Id $wmiService.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {{
                        Write-Host "  Process: $($proc.ProcessName) (PID: $($wmiService.ProcessId))"
                        Write-Host "  Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 1)) MB"
                    }}
                }}
                Write-Host ""
                Write-Host "No changes made (dry run mode)"
            }} else {{
                Write-Host "[DRY RUN] Service '{service_name}' not found"
            }}
            """
            audit_log(name, service_name, "DRY_RUN")
            output = run_powershell(script)
            return [TextContent(type="text", text=output)]

        if check_admin_privileges():
            # Run directly if already admin
            if name == "stop_service":
                script = f"""
                try {{
                    $service = Get-Service -Name '{service_name}' -ErrorAction Stop
                    Write-Host "Stopping service: $($service.DisplayName) ($($service.Name))"
                    Stop-Service -Name '{service_name}' -Force
                    Write-Host "Service '{service_name}' stopped successfully"
                }} catch {{
                    Write-Host "Error stopping service '{service_name}': $_"
                }}
                """
            elif name == "start_service":
                script = f"""
                try {{
                    $service = Get-Service -Name '{service_name}' -ErrorAction Stop
                    Write-Host "Starting service: $($service.DisplayName) ($($service.Name))"
                    Start-Service -Name '{service_name}'
                    Write-Host "Service '{service_name}' started successfully"
                }} catch {{
                    Write-Host "Error starting service '{service_name}': $_"
                }}
                """
            else:  # restart_service
                script = f"""
                try {{
                    $service = Get-Service -Name '{service_name}' -ErrorAction Stop
                    Write-Host "Restarting service: $($service.DisplayName) ($($service.Name))"
                    Restart-Service -Name '{service_name}' -Force
                    Write-Host "Service '{service_name}' restarted successfully"
                }} catch {{
                    Write-Host "Error restarting service '{service_name}': $_"
                }}
                """
            audit_log(name, service_name, "EXECUTED_AS_ADMIN")
            output = run_powershell(script)
        else:
            output = run_elevated_operation(f"{action}-service", service_name, force)

        return [TextContent(type="text", text=output)]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Main function"""
    logger.info("Starting Generic Windows Process and Service Management MCP Server with UAC Elevation")
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())