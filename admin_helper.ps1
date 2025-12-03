#!/usr/bin/env powershell
<#
.SYNOPSIS
WinProc MCP Admin Helper Script
Handles elevated operations separately from main MCP server

.PARAMETER Operation
The operation to perform (kill-process, kill-multiple, kill-by-port, stop-service, start-service, restart-service)

.PARAMETER Target
The target for the operation (PID, service name, port, etc.)

.PARAMETER Force
Skip confirmation prompts
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("kill-process", "kill-multiple", "kill-by-port", "stop-service", "start-service", "restart-service")]
    [string]$Operation,
    
    [Parameter(Mandatory=$true)]
    [string]$Target,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Check if running as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script requires administrator privileges" -ForegroundColor Red
    Write-Host "This script should be called via UAC elevation from the MCP server" -ForegroundColor Yellow
    exit 1
}

function Stop-ProcessById {
    param([int]$ProcessId, [bool]$ForceKill)
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            Write-Host "Process with PID $ProcessId not found" -ForegroundColor Red
            return $false
        }
        
        if (-not $ForceKill) {
            Write-Host "About to terminate:" -ForegroundColor Yellow
            Write-Host "  Process: $($process.ProcessName) (PID: $ProcessId)" -ForegroundColor White
            Write-Host "  Memory: $([math]::Round($process.WorkingSet64 / 1MB, 1)) MB" -ForegroundColor White
            
            $confirmation = Read-Host "Type 'YES' to confirm termination"
            if ($confirmation -ne 'YES') {
                Write-Host "Operation cancelled" -ForegroundColor Green
                return $false
            }
        }
        
        Write-Host "Terminating process: $($process.ProcessName) (PID: $ProcessId)" -ForegroundColor Yellow
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Host "Process $ProcessId terminated successfully" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Host "Error terminating process $ProcessId`: $_" -ForegroundColor Red
        return $false
    }
}

function Stop-MultipleProcesses {
    param([int[]]$ProcessIds, [bool]$ForceKill)
    
    $validProcesses = @()
    
    # Validate all processes first
    foreach ($processId in $ProcessIds) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            $validProcesses += @{
                PID = $processId
                Name = $process.ProcessName
                Memory = [math]::Round($process.WorkingSet64 / 1MB, 1)
            }
        } else {
            Write-Host "Warning: Process PID $processId not found" -ForegroundColor Yellow
        }
    }
    
    if ($validProcesses.Count -eq 0) {
        Write-Host "No valid processes found to terminate" -ForegroundColor Red
        return $false
    }
    
    if (-not $ForceKill) {
        Write-Host "About to terminate $($validProcesses.Count) processes:" -ForegroundColor Yellow
        foreach ($proc in $validProcesses) {
            Write-Host "  $($proc.Name) (PID: $($proc.PID)) - $($proc.Memory) MB" -ForegroundColor White
        }
        
        $confirmation = Read-Host "Type 'YES' to confirm termination of ALL processes"
        if ($confirmation -ne 'YES') {
            Write-Host "Operation cancelled" -ForegroundColor Green
            return $false
        }
    }
    
    $successCount = 0
    foreach ($proc in $validProcesses) {
        try {
            Write-Host "Terminating: $($proc.Name) (PID: $($proc.PID))" -ForegroundColor Yellow
            Stop-Process -Id $proc.PID -Force -ErrorAction Stop
            Write-Host "  Successfully terminated PID $($proc.PID)" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host "  Error terminating PID $($proc.PID)`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "Terminated $successCount of $($validProcesses.Count) processes" -ForegroundColor Cyan
    return $successCount -gt 0
}

function Stop-ProcessesByPort {
    param([int[]]$Ports, [bool]$ForceKill)
    
    $processesToKill = @()
    
    foreach ($port in $Ports) {
        $tcpConnections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        
        foreach ($conn in $tcpConnections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                $processesToKill += @{
                    PID = $conn.OwningProcess
                    Name = $process.ProcessName
                    Port = $port
                    Address = $conn.LocalAddress
                    Memory = [math]::Round($process.WorkingSet64 / 1MB, 1)
                }
            }
        }
    }
    
    if ($processesToKill.Count -eq 0) {
        Write-Host "No processes found listening on ports: $($Ports -join ', ')" -ForegroundColor Yellow
        return $false
    }
    
    # Remove duplicates by PID
    $uniqueProcesses = $processesToKill | Group-Object PID | ForEach-Object { $_.Group[0] }
    
    if (-not $ForceKill) {
        Write-Host "About to terminate $($uniqueProcesses.Count) processes using ports $($Ports -join ', '):" -ForegroundColor Yellow
        foreach ($proc in $uniqueProcesses) {
            Write-Host "  $($proc.Name) (PID: $($proc.PID)) - Port $($proc.Port) - $($proc.Memory) MB" -ForegroundColor White
        }
        
        $confirmation = Read-Host "Type 'YES' to confirm termination of ALL processes"
        if ($confirmation -ne 'YES') {
            Write-Host "Operation cancelled" -ForegroundColor Green
            return $false
        }
    }
    
    $successCount = 0
    foreach ($proc in $uniqueProcesses) {
        try {
            Write-Host "Terminating: $($proc.Name) (PID: $($proc.PID)) using port $($proc.Port)" -ForegroundColor Yellow
            Stop-Process -Id $proc.PID -Force -ErrorAction Stop
            Write-Host "  Successfully terminated PID $($proc.PID)" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host "  Error terminating PID $($proc.PID)`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "Terminated $successCount of $($uniqueProcesses.Count) processes" -ForegroundColor Cyan
    return $successCount -gt 0
}

function Invoke-ServiceOperation {
    param([string]$ServiceName, [string]$Action, [bool]$ForceAction)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "Service '$ServiceName' not found" -ForegroundColor Red
        return $false
    }
    
    Write-Host "Service: $($service.Name) - $($service.DisplayName)" -ForegroundColor Cyan
    Write-Host "Current Status: $($service.Status)" -ForegroundColor White
    
    if (-not $ForceAction -and $Action -in @("stop", "restart")) {
        $confirmation = Read-Host "Type 'YES' to confirm $Action operation"
        if ($confirmation -ne 'YES') {
            Write-Host "Operation cancelled" -ForegroundColor Green
            return $false
        }
    }
    
    try {
        switch ($Action) {
            "stop" {
                Write-Host "Stopping service..." -ForegroundColor Yellow
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Write-Host "Service stopped successfully" -ForegroundColor Green
            }
            "start" {
                Write-Host "Starting service..." -ForegroundColor Yellow
                Start-Service -Name $ServiceName -ErrorAction Stop
                Write-Host "Service started successfully" -ForegroundColor Green
            }
            "restart" {
                Write-Host "Restarting service..." -ForegroundColor Yellow
                Restart-Service -Name $ServiceName -Force -ErrorAction Stop
                Write-Host "Service restarted successfully" -ForegroundColor Green
            }
        }
        return $true
    } catch {
        Write-Host "Error during $Action operation: $_" -ForegroundColor Red
        return $false
    }
}

# Main execution
Write-Host "=== Admin Helper Script ===" -ForegroundColor Cyan
Write-Host "Operation: $Operation" -ForegroundColor White
Write-Host "Target: $Target" -ForegroundColor White
Write-Host "Force: $Force" -ForegroundColor White
Write-Host ""

$success = $false

switch ($Operation) {
    "kill-process" {
        $processId = [int]$Target
        $success = Stop-ProcessById -ProcessId $processId -ForceKill $Force
    }
    
    "kill-multiple" {
        $processIds = $Target -split ',' | ForEach-Object { [int]$_.Trim() }
        $success = Stop-MultipleProcesses -ProcessIds $processIds -ForceKill $Force
    }
    
    "kill-by-port" {
        $ports = $Target -split ',' | ForEach-Object { [int]$_.Trim() }
        $success = Stop-ProcessesByPort -Ports $ports -ForceKill $Force
    }
    
    "stop-service" {
        $success = Invoke-ServiceOperation -ServiceName $Target -Action "stop" -ForceAction $Force
    }
    
    "start-service" {
        $success = Invoke-ServiceOperation -ServiceName $Target -Action "start" -ForceAction $Force
    }
    
    "restart-service" {
        $success = Invoke-ServiceOperation -ServiceName $Target -Action "restart" -ForceAction $Force
    }
}

if ($success) {
    Write-Host "`nOperation completed successfully" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nOperation failed or was cancelled" -ForegroundColor Red
    exit 1
}