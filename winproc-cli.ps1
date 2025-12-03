#!/usr/bin/env powershell
<#
.SYNOPSIS
WinProc CLI - Direct command-line interface for Windows process and service management

.DESCRIPTION
This script provides direct CLI access to WinProc MCP functions without needing Claude Code.
You can check ports, find processes, get service info, and perform management operations.

.PARAMETER Command
The command to execute (check-ports, find-service, process-info, kill-port, etc.)

.PARAMETER Target
The target for the command (port numbers, service name, PID, etc.)

.PARAMETER Force
Skip confirmation prompts for destructive operations

.EXAMPLE
.\winproc-cli.ps1 check-ports 3000,3001,3002
.\winproc-cli.ps1 find-service "*SQL*"
.\winproc-cli.ps1 process-info 1234
.\winproc-cli.ps1 kill-port 8080 -Force

#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("check-ports", "all-ports", "find-service", "service-info", "process-info", "kill-process", "kill-port", "kill-multiple", "stop-service", "start-service", "restart-service", "definitions", "help")]
    [string]$Command = "help",

    [Parameter(Mandatory=$false, ValueFromRemainingArguments=$true)]
    [string[]]$Target,

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [Alias("d", "def")]
    [switch]$Definitions
)

# Colors for output
$colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Header = "Magenta"
    Definition = "DarkCyan"
}

# Metric definitions organized by category
$MetricDefinitions = @{
    # Process Information
    "Process Name" = 'The executable name of the running process without the file extension.'
    "PID" = 'Process Identifier - A unique number assigned by Windows to identify this specific process instance.'
    "Memory Usage" = 'Current RAM consumption (Working Set) - the physical memory actively being used by the process.'
    "CPU Time" = 'Total processor time consumed since process started. Format: hours:minutes:seconds.milliseconds.'
    "Start Time" = 'The date and time when this process was launched.'
    "Priority" = 'Base scheduling priority (0-31). Higher values get more CPU time. Normal apps typically run at 8.'
    "Thread Count" = 'Number of execution threads. More threads can mean parallel operations or background tasks.'
    "Command Line" = 'The full command used to launch the process including all arguments and parameters.'
    "Executable Path" = 'The complete file system path to the .exe file running this process.'
    # Process Chain
    "Parent Process" = 'The process that spawned/created this process. Useful for understanding process relationships.'
    "Grandparent" = 'The process that created the parent process - helps trace the full process lineage.'
    "Child Processes" = 'Processes spawned by this process. Killing the parent may orphan or terminate children.'
    # Network Information
    "Listening Ports" = 'TCP ports where the process is waiting for incoming connections (server mode).'
    "Active Connections" = 'Established TCP connections to/from remote systems showing local and remote endpoints.'
    "Local Address" = 'The IP address and port on your machine. 0.0.0.0 means listening on all interfaces.'
    "Remote Address" = 'The IP address and port of the connected remote system.'
    "Connection State" = 'TCP connection status: Listen (waiting) / Established (connected) / TimeWait (closing).'
    # Loaded Modules
    "Loaded Modules" = 'DLL files (Dynamic Link Libraries) loaded into the process memory space.'
    "Module Size" = 'Memory footprint of each loaded DLL. Large modules may indicate heavy dependencies.'
    # Memory Metrics
    "Uptime" = 'How long the process has been running since it started.'
    "Working Set" = 'RAM currently in use by the process. Fluctuates as Windows may trim memory for other apps.'
    "Peak Working Set" = 'Maximum RAM the process has ever used - indicates highest memory demand point.'
    "Virtual Memory" = 'Total address space reserved (not all may be in physical RAM). Includes memory-mapped files.'
    "Private Memory" = 'Memory exclusively allocated to this process that cannot be shared with other processes.'
    "Peak Virtual Memory" = 'Maximum virtual address space the process has ever reserved.'
    # Service Information
    "Service Name" = 'The internal Windows service identifier used in commands and scripts.'
    "Display Name" = 'Human-readable name shown in the Services management console.'
    "Service Status" = 'Current state: Running / Stopped / Paused / Starting / Stopping.'
    "Start Type" = 'How the service starts: Automatic (at boot) / Manual (on demand) / Disabled.'
    # Port Information
    "Port" = 'A numbered endpoint (0-65535) for network communication. Well-known ports are 0-1023.'
    "Protocol" = 'Network protocol: TCP (connection-oriented / reliable) or UDP (connectionless / fast).'
}

function Show-Definitions {
    param([string]$Category = "all")

    Write-Host ""
    Write-Host "=== WinProc Metric Definitions ===" -ForegroundColor $colors.Header
    Write-Host "Understanding what each metric means" -ForegroundColor $colors.Info
    Write-Host ""

    $categories = @{
        "process" = @("Process Name"; "PID"; "Memory Usage"; "CPU Time"; "Start Time"; "Priority"; "Thread Count"; "Command Line"; "Executable Path")
        "chain" = @("Parent Process"; "Grandparent"; "Child Processes")
        "network" = @("Listening Ports"; "Active Connections"; "Local Address"; "Remote Address"; "Connection State"; "Port"; "Protocol")
        "modules" = @("Loaded Modules"; "Module Size")
        "memory" = @("Uptime"; "Working Set"; "Peak Working Set"; "Virtual Memory"; "Private Memory"; "Peak Virtual Memory")
        "service" = @("Service Name"; "Display Name"; "Service Status"; "Start Type")
    }

    $categoryTitles = @{
        "process" = "Process Information"
        "chain" = "Process Chain"
        "network" = "Network Information"
        "modules" = "Loaded Modules"
        "memory" = "Memory Metrics"
        "service" = "Service Information"
    }

    function Write-DefinitionCategory {
        param([string]$CategoryKey)
        Write-Host "--- $($categoryTitles[$CategoryKey]) ---" -ForegroundColor $colors.Warning
        foreach ($metric in $categories[$CategoryKey]) {
            Write-Host "  $metric" -ForegroundColor $colors.Success -NoNewline
            Write-Host ": " -NoNewline
            Write-Host $MetricDefinitions[$metric] -ForegroundColor $colors.Definition
        }
        Write-Host ""
    }

    if ($Category -eq "all") {
        foreach ($cat in @("process"; "chain"; "network"; "modules"; "memory"; "service")) {
            Write-DefinitionCategory -CategoryKey $cat
        }
    } elseif ($categories.ContainsKey($Category.ToLower())) {
        Write-DefinitionCategory -CategoryKey $Category.ToLower()
    } else {
        Write-Host "Unknown category: $Category" -ForegroundColor $colors.Error
        Write-Host "Available categories: process / chain / network / modules / memory / service / all" -ForegroundColor $colors.Info
    }

    Write-Host "TIP: Use -Definitions (-d) flag with process-info to show definitions alongside output" -ForegroundColor $colors.Info
    Write-Host "     Example: .\winproc-cli.ps1 process-info 1234 -d" -ForegroundColor $colors.Info
    Write-Host ""
}

function Show-CompactDefinitions {
    Write-Host ""
    Write-Host "=== Quick Reference ===" -ForegroundColor $colors.Header
    Write-Host "Working Set    : RAM currently in use (may be trimmed by Windows)" -ForegroundColor $colors.Definition
    Write-Host "Peak Working   : Highest RAM usage ever recorded" -ForegroundColor $colors.Definition
    Write-Host "Virtual Memory : Total address space reserved (not all in RAM)" -ForegroundColor $colors.Definition
    Write-Host "Private Memory : Memory exclusive to this process" -ForegroundColor $colors.Definition
    Write-Host "CPU Time       : Total processor time consumed since start" -ForegroundColor $colors.Definition
    Write-Host "Priority       : Scheduling priority (8 = normal)" -ForegroundColor $colors.Definition
    Write-Host ""
    Write-Host "Run 'definitions' command for full metric explanations" -ForegroundColor $colors.Info
    Write-Host ""
}

function Show-Help {
    Write-Host ""
    Write-Host "=== WinProc CLI ===" -ForegroundColor $colors.Header
    Write-Host "Direct command-line interface for port and process management" -ForegroundColor $colors.Info
    Write-Host ""

    Write-Host "DISCOVERY COMMANDS (No admin required):" -ForegroundColor $colors.Header
    Write-Host "  check-ports <ports>     - Check what's listening on specific ports"
    Write-Host "                           Example: check-ports 3000,3001,3002"
    Write-Host "  all-ports              - Show all listening ports on the system"
    Write-Host "  find-service <pattern> - Find services by name (supports wildcards)"
    Write-Host "                           Example: find-service '*SQL*'"
    Write-Host "  service-info <name>    - Get detailed info about a service"
    Write-Host "  process-info <PID>     - Get detailed info about a process"
    Write-Host "                           Use -d flag to include metric definitions"
    Write-Host "  definitions [category] - Show what each metric means"
    Write-Host "                           Categories: process / chain / network / modules / memory / service"
    Write-Host ""

    Write-Host "MANAGEMENT COMMANDS (Require admin/UAC):" -ForegroundColor $colors.Header
    Write-Host "  kill-process <PID>     - Kill a process by PID"
    Write-Host "  kill-port <ports>      - Kill all processes using specific ports"
    Write-Host "  kill-multiple <PIDs>   - Kill multiple processes"
    Write-Host "  stop-service <name>    - Stop a Windows service"
    Write-Host "  start-service <name>   - Start a Windows service"
    Write-Host "  restart-service <name> - Restart a Windows service"
    Write-Host ""

    Write-Host "OPTIONS:" -ForegroundColor $colors.Header
    Write-Host "  -Force                 - Skip confirmation prompts"
    Write-Host "  -Definitions (-d)      - Show metric definitions with output"
    Write-Host ""

    Write-Host "EXAMPLES:" -ForegroundColor $colors.Header
    Write-Host "  .\winproc-cli.ps1 check-ports 3000-3005"
    Write-Host "  .\winproc-cli.ps1 find-service 'Docker*'"
    Write-Host "  .\winproc-cli.ps1 kill-port 8080 -Force"
    Write-Host "  .\winproc-cli.ps1 all-ports | findstr :80"
    Write-Host ""
}

function Check-Ports {
    param([string]$PortList)

    if (-not $PortList -or $PortList -eq "") {
        Write-Host "Error: Port list required" -ForegroundColor $colors.Error
        Write-Host "Example: check-ports 3000,3001,3002 or check-ports 3000-3005"
        return
    }

    # Parse port ranges and lists
    $ports = @()
    $PortList -split ',' | ForEach-Object {
        $range = $_.Trim()
        if ($range -match '^(\d+)-(\d+)$') {
            $start = [int]$matches[1]
            $end = [int]$matches[2]
            $ports += $start..$end
        } else {
            $ports += [int]$range
        }
    }

    Write-Host "Checking ports: $($ports -join ', ')" -ForegroundColor $colors.Info
    Write-Host ""

    $found = $false
    foreach ($port in $ports) {
        $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue

        if ($connections) {
            $found = $true
            foreach ($conn in $connections) {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                Write-Host "Port $port - " -NoNewline -ForegroundColor $colors.Warning
                Write-Host "$($process.ProcessName) " -NoNewline -ForegroundColor $colors.Success
                Write-Host "(PID: $($conn.OwningProcess)) " -NoNewline
                Write-Host "[$($conn.LocalAddress)]" -ForegroundColor $colors.Info
            }
        }
    }

    if (-not $found) {
        Write-Host "No processes found listening on the specified ports" -ForegroundColor $colors.Warning
    }
}

function Get-AllPorts {
    Write-Host "All listening ports:" -ForegroundColor $colors.Info
    Write-Host ""

    $connections = Get-NetTCPConnection -State Listen | Sort-Object LocalPort

    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "Port $($conn.LocalPort) - " -NoNewline -ForegroundColor $colors.Warning
        Write-Host "$($process.ProcessName) " -NoNewline -ForegroundColor $colors.Success
        Write-Host "(PID: $($conn.OwningProcess)) " -NoNewline
        Write-Host "[$($conn.LocalAddress)]" -ForegroundColor $colors.Info
    }
}

function Find-ServiceByPattern {
    param([string]$Pattern)

    if (-not $Pattern) {
        Write-Host "Error: Service pattern required" -ForegroundColor $colors.Error
        Write-Host "Example: find-service '*SQL*' or find-service 'Docker'"
        return
    }

    Write-Host "Finding services matching: $Pattern" -ForegroundColor $colors.Info
    Write-Host ""

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like $Pattern -or $_.DisplayName -like $Pattern
    }

    if ($services) {
        $serviceCount = @($services).Count
        Write-Host "Found $serviceCount service(s) matching '$Pattern'" -ForegroundColor $colors.Info
        Write-Host ""

        foreach ($service in $services) {
            Write-Host "=== $($service.Name) ===" -ForegroundColor $colors.Header
            Write-Host "Display Name: $($service.DisplayName)"
            Write-Host "Status: $($service.Status)" -ForegroundColor $(
                if ($service.Status -eq 'Running') { $colors.Success } else { $colors.Warning }
            )
            Write-Host "Start Type: $($service.StartType)"

            # Get additional service details via WMI
            $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            if ($wmiService) {
                if ($wmiService.PathName) {
                    Write-Host "Executable: $($wmiService.PathName)" -ForegroundColor $colors.Info
                }
                if ($wmiService.StartName) {
                    Write-Host "Run As: $($wmiService.StartName)"
                }
                if ($wmiService.Description) {
                    $desc = if ($wmiService.Description.Length -gt 100) {
                        $wmiService.Description.Substring(0, 100) + "..."
                    } else {
                        $wmiService.Description
                    }
                    Write-Host "Description: $desc" -ForegroundColor $colors.Definition
                }
            }

            # Try to find associated processes
            $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*$($service.Name)*" }
            if ($processes) {
                Write-Host "Associated Processes:" -ForegroundColor $colors.Warning
                foreach ($proc in $processes) {
                    Write-Host "  └─ $($proc.ProcessName) (PID: $($proc.Id)) - Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 1)) MB" -ForegroundColor $colors.Success
                }
            }

            # Check if service process is listening on any ports
            if ($wmiService -and $wmiService.ProcessId -and $wmiService.ProcessId -gt 0) {
                $tcpConnections = Get-NetTCPConnection -OwningProcess $wmiService.ProcessId -State Listen -ErrorAction SilentlyContinue
                if ($tcpConnections) {
                    Write-Host "Listening Ports:" -ForegroundColor $colors.Warning
                    foreach ($conn in $tcpConnections) {
                        Write-Host "  └─ Port $($conn.LocalPort) [$($conn.LocalAddress)]" -ForegroundColor $colors.Success
                    }
                }
            }

            Write-Host ""
        }
    } else {
        Write-Host "No services found matching pattern: $Pattern" -ForegroundColor $colors.Warning
    }
}

function Get-ProcessChainInfo {
    param(
        [string]$ProcessId,
        [switch]$ShowDefinitions
    )

    try {
        $targetProcess = Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        Write-Host "Process with PID '$ProcessId' not found" -ForegroundColor $colors.Error
        return
    }

    # Get WMI process info for parent details
    $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "=== Process Information ===" -ForegroundColor $colors.Header
    Write-Host "Process Name: $($targetProcess.ProcessName)" -ForegroundColor $colors.Success
    Write-Host "PID: $($targetProcess.Id)"
    Write-Host "Memory Usage: $([math]::Round($targetProcess.WorkingSet64 / 1MB, 1)) MB"

    # Format CPU Time properly
    $cpuTime = if ($targetProcess.TotalProcessorTime) {
        $targetProcess.TotalProcessorTime.ToString("hh\:mm\:ss\.fff")
    } else {
        "Not available"
    }
    Write-Host "CPU Time: $cpuTime"

    # Format Start Time properly
    $startTime = if ($targetProcess.StartTime) {
        $targetProcess.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        "Not available"
    }
    Write-Host "Start Time: $startTime"

    Write-Host "Priority: $($targetProcess.BasePriority)"
    Write-Host "Thread Count: $($targetProcess.Threads.Count)"

    # Get command line and path info
    if ($wmiProcess) {
        $cmdLine = if ($wmiProcess.CommandLine) { $wmiProcess.CommandLine } else { "Not available" }
        $exePath = if ($wmiProcess.ExecutablePath) { $wmiProcess.ExecutablePath } else { "Not available" }
        Write-Host "Command Line: $cmdLine" -ForegroundColor $colors.Info
        Write-Host "Executable Path: $exePath"
    } else {
        Write-Host "Command Line: Not available (WMI access denied)" -ForegroundColor $colors.Warning
        Write-Host "Executable Path: Not available (WMI access denied)" -ForegroundColor $colors.Warning
    }

    # Get parent process info
    Write-Host ""
    Write-Host "=== Process Chain ===" -ForegroundColor $colors.Header

    if ($wmiProcess -and $wmiProcess.ParentProcessId) {
        $parentProcess = Get-Process -Id $wmiProcess.ParentProcessId -ErrorAction SilentlyContinue
        if ($parentProcess) {
            Write-Host "Parent Process: $($parentProcess.ProcessName) (PID: $($parentProcess.Id))" -ForegroundColor $colors.Warning

            # Get grandparent if available
            $parentWmi = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($parentProcess.Id)" -ErrorAction SilentlyContinue
            if ($parentWmi -and $parentWmi.ParentProcessId) {
                $grandparentProcess = Get-Process -Id $parentWmi.ParentProcessId -ErrorAction SilentlyContinue
                if ($grandparentProcess) {
                    Write-Host "  └─ Grandparent: $($grandparentProcess.ProcessName) (PID: $($grandparentProcess.Id))" -ForegroundColor $colors.Info
                }
            }
        } else {
            Write-Host "Parent Process: (PID: $($wmiProcess.ParentProcessId)) - Process no longer exists" -ForegroundColor $colors.Warning
        }
    } else {
        Write-Host "Parent Process: Not available (may be system process)" -ForegroundColor $colors.Info
    }

    # Get child processes
    $childProcesses = Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if ($childProcesses) {
        Write-Host ""
        Write-Host "Child Processes:" -ForegroundColor $colors.Warning
        foreach ($child in $childProcesses) {
            $childProcess = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
            if ($childProcess) {
                Write-Host "  └─ $($childProcess.ProcessName) (PID: $($child.ProcessId)) - Memory: $([math]::Round($childProcess.WorkingSet64 / 1MB, 1)) MB" -ForegroundColor $colors.Success

                # Show grandchildren (one level deeper)
                $grandchildren = Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = $($child.ProcessId)" -ErrorAction SilentlyContinue
                foreach ($grandchild in $grandchildren) {
                    $grandchildProcess = Get-Process -Id $grandchild.ProcessId -ErrorAction SilentlyContinue
                    if ($grandchildProcess) {
                        Write-Host "      └─ $($grandchildProcess.ProcessName) (PID: $($grandchild.ProcessId))" -ForegroundColor $colors.Info
                    }
                }
            }
        }
    } else {
        Write-Host "Child Processes: None" -ForegroundColor $colors.Info
    }

    # Check if process is listening on any ports
    Write-Host ""
    Write-Host "=== Network Information ===" -ForegroundColor $colors.Header
    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $ProcessId }

    if ($tcpConnections) {
        Write-Host "Listening Ports:" -ForegroundColor $colors.Warning
        $listeningPorts = $tcpConnections | Where-Object { $_.State -eq "Listen" } | Sort-Object LocalPort -Unique
        foreach ($conn in $listeningPorts) {
            Write-Host "  └─ Port $($conn.LocalPort) [$($conn.LocalAddress)]" -ForegroundColor $colors.Success
        }

        $activePorts = $tcpConnections | Where-Object { $_.State -ne "Listen" } | Sort-Object LocalPort -Unique
        if ($activePorts) {
            Write-Host "Active Connections:" -ForegroundColor $colors.Warning
            foreach ($conn in $activePorts) {
                Write-Host "  └─ $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($conn.State)]" -ForegroundColor $colors.Info
            }
        }
    } else {
        Write-Host "Network Connections: None" -ForegroundColor $colors.Info
    }

    # Show loaded modules (DLLs) - top 10 by size
    Write-Host ""
    Write-Host "=== Loaded Modules (Top 10 by Size) ===" -ForegroundColor $colors.Header
    try {
        $modules = $targetProcess.Modules | Sort-Object ModuleMemorySize -Descending | Select-Object -First 10
        if ($modules -and $modules.Count -gt 0) {
            foreach ($module in $modules) {
                $sizeKB = [math]::Round($module.ModuleMemorySize / 1KB, 1)
                Write-Host "  └─ $($module.ModuleName) - $sizeKB KB" -ForegroundColor $colors.Info
            }
        } else {
            Write-Host "  No modules accessible (may be system process or access denied)" -ForegroundColor $colors.Warning
        }
    } catch {
        Write-Host "  Modules: Access denied (likely system process or insufficient privileges)" -ForegroundColor $colors.Warning
    }

    # Add process uptime calculation
    Write-Host ""
    Write-Host "=== Additional Information ===" -ForegroundColor $colors.Header
    if ($targetProcess.StartTime) {
        $uptime = (Get-Date) - $targetProcess.StartTime
        $uptimeString = "{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds" -f $uptime
        Write-Host "Uptime: $uptimeString" -ForegroundColor $colors.Info
    }

    # Show process working set details
    Write-Host "Working Set: $([math]::Round($targetProcess.WorkingSet64 / 1MB, 1)) MB"
    Write-Host "Peak Working Set: $([math]::Round($targetProcess.PeakWorkingSet64 / 1MB, 1)) MB"
    Write-Host "Virtual Memory: $([math]::Round($targetProcess.VirtualMemorySize64 / 1MB, 1)) MB"
    Write-Host "Private Memory: $([math]::Round($targetProcess.PrivateMemorySize64 / 1MB, 1)) MB"
    Write-Host "Peak Virtual Memory: $([math]::Round($targetProcess.PeakVirtualMemorySize64 / 1MB, 1)) MB"

    # Show definitions if requested
    if ($ShowDefinitions) {
        Show-CompactDefinitions
    } else {
        Write-Host ""
        Write-Host "TIP: Use -d flag to see metric definitions" -ForegroundColor $colors.Info
        Write-Host ""
    }
}

function Call-AdminHelper {
    param([string]$Operation, [string]$TargetValue, [bool]$ForceOperation)

    $scriptPath = Join-Path $PSScriptRoot "admin_helper.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "Error: admin_helper.ps1 not found at $scriptPath" -ForegroundColor $colors.Error
        return $false
    }

    try {
        $forceArg = if ($ForceOperation) { " -Force" } else { "" }
        $cmd = "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File `"$scriptPath`" -Operation $Operation -Target `"$TargetValue`"$forceArg' -Verb RunAs -Wait"

        Write-Host "Requesting admin privileges for operation..." -ForegroundColor $colors.Warning
        Invoke-Expression $cmd
        return $true
    } catch {
        Write-Host "Error executing admin operation: $_" -ForegroundColor $colors.Error
        return $false
    }
}

# Main execution
$TargetString = if ($Target) { $Target -join "," } else { "" }

switch ($Command) {
    "check-ports" {
        Check-Ports -PortList $TargetString
    }

    "all-ports" {
        Get-AllPorts
    }

    "find-service" {
        Find-ServiceByPattern -Pattern $TargetString
    }

    "service-info" {
        if (-not $TargetString) {
            Write-Host "Error: Service name required" -ForegroundColor $colors.Error
            return
        }
        $service = Get-Service -Name $TargetString -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "Service: $($service.Name)" -ForegroundColor $colors.Header
            Write-Host "Display Name: $($service.DisplayName)"
            Write-Host "Status: $($service.Status)" -ForegroundColor $(
                if ($service.Status -eq 'Running') { $colors.Success } else { $colors.Warning }
            )
            Write-Host "Start Type: $($service.StartType)"

            if ($Definitions) {
                Write-Host ""
                Write-Host "=== Quick Reference ===" -ForegroundColor $colors.Header
                Write-Host "Service Name : Internal Windows service identifier" -ForegroundColor $colors.Definition
                Write-Host "Display Name : Human-readable name in Services console" -ForegroundColor $colors.Definition
                Write-Host "Status       : Current state (Running / Stopped / etc.)" -ForegroundColor $colors.Definition
                Write-Host "Start Type   : Automatic (boot) / Manual (demand) / Disabled" -ForegroundColor $colors.Definition
                Write-Host ""
            } else {
                Write-Host ""
                Write-Host "TIP: Use -d flag to see metric definitions" -ForegroundColor $colors.Info
            }
        } else {
            Write-Host "Service '$TargetString' not found" -ForegroundColor $colors.Error
        }
    }

    "process-info" {
        if (-not $TargetString) {
            Write-Host "Error: Process ID required" -ForegroundColor $colors.Error
            return
        }
        Get-ProcessChainInfo -ProcessId $TargetString -ShowDefinitions:$Definitions
    }

    "definitions" {
        $cat = if ($TargetString) { $TargetString } else { "all" }
        Show-Definitions -Category $cat
    }

    "kill-process" {
        if (-not $TargetString) {
            Write-Host "Error: Process ID required" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "kill-process" -TargetValue $TargetString -ForceOperation $Force
    }

    "kill-port" {
        if (-not $TargetString) {
            Write-Host "Error: Port number(s) required" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "kill-by-port" -TargetValue $TargetString -ForceOperation $Force
    }

    "kill-multiple" {
        if (-not $TargetString) {
            Write-Host "Error: Process IDs required (comma-separated)" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "kill-multiple" -TargetValue $TargetString -ForceOperation $Force
    }

    "stop-service" {
        if (-not $TargetString) {
            Write-Host "Error: Service name required" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "stop-service" -TargetValue $TargetString -ForceOperation $Force
    }

    "start-service" {
        if (-not $TargetString) {
            Write-Host "Error: Service name required" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "start-service" -TargetValue $TargetString -ForceOperation $Force
    }

    "restart-service" {
        if (-not $TargetString) {
            Write-Host "Error: Service name required" -ForegroundColor $colors.Error
            return
        }
        Call-AdminHelper -Operation "restart-service" -TargetValue $TargetString -ForceOperation $Force
    }

    "help" {
        Show-Help
    }

    default {
        Write-Host "Unknown command: $Command" -ForegroundColor $colors.Error
        Show-Help
    }
}
