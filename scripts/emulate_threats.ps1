<#
.SYNOPSIS
    Safe threat simulation script for validating Splunk detections.
.DESCRIPTION
    Simulates MITRE ATT&CK techniques T1059.001, T1036.003, and T1105
    to trigger Sysmon EventCodes 1, 8, and 11 for detection testing.
.NOTES
    Run as Administrator. All actions are harmless — no real malware.
#>

Write-Host "[*] Starting threat simulation..." -ForegroundColor Cyan

# T1059.001 — PowerShell Execution Policy Bypass
Write-Host "[!] Simulating T1059.001: PowerShell bypass..." -ForegroundColor Yellow
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Host 'Simulation: bypass executed'"

# T1036.003 — Binary Masquerading (copy cmd.exe as svchost.exe)
Write-Host "[!] Simulating T1036.003: Binary masquerading..." -ForegroundColor Yellow
$TempDir = Join-Path $env:TEMP "sim_test"
if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }
$FakeProc = Join-Path $TempDir "svchost.exe"
Copy-Item "C:\Windows\System32\cmd.exe" $FakeProc -Force
Start-Process -FilePath $FakeProc -ArgumentList "/c dir" -Wait -NoNewWindow
Write-Host "[*] Masqueraded binary executed: $FakeProc" -ForegroundColor Green

# T1105 — File drop in Temp directory
Write-Host "[!] Simulating T1105: File drop in Temp..." -ForegroundColor Yellow
$MockFile = Join-Path $env:TEMP "mock_payload.txt"
"Simulated payload — detection test only." | Out-File -FilePath $MockFile -Force
Write-Host "[*] File created at: $MockFile" -ForegroundColor Green

# Cleanup
Write-Host "[*] Cleaning up..." -ForegroundColor Cyan
Remove-Item $FakeProc -Force -ErrorAction SilentlyContinue
Remove-Item $TempDir -Force -ErrorAction SilentlyContinue
Remove-Item $MockFile -Force -ErrorAction SilentlyContinue

Write-Host "[+] Done. Check Splunk index=endpoint for EventCode 1, 8, and 11." -ForegroundColor Green