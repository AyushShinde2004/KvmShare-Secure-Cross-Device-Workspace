<#
 Installs KvmShare for the current user:
   * private virtualenv + dependencies
   * Windows Firewall rules limited to the PRIVATE profile and the LOCAL SUBNET (never public/internet)
   * a logon task that starts the daemon hidden
 Run in a normal PowerShell. Firewall rules need one elevation prompt.
 -Elevated  runs the daemon at highest privilege so it can inject into elevated (admin) windows.
#>
param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $env:LOCALAPPDATA 'KvmShare\venv'
if (-not (Test-Path "$venv\Scripts\python.exe")) { python -m venv $venv }
& "$venv\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
& "$venv\Scripts\python.exe" -m pip install -r "$root\requirements.txt"
& "$venv\Scripts\python.exe" -m pip install --no-deps -e $root | Out-Null

$pyw = "$venv\Scripts\pythonw.exe"
$fw = @"
Remove-NetFirewallRule -DisplayName 'KvmShare*' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'KvmShare TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 24800,24802 -Profile Private -RemoteAddress LocalSubnet -Program '$pyw' | Out-Null
New-NetFirewallRule -DisplayName 'KvmShare discovery' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 24801 -Profile Private -RemoteAddress LocalSubnet -Program '$pyw' | Out-Null
"@
Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-Command',$fw

$action  = New-ScheduledTaskAction -Execute $pyw -Argument '-m kvmshare run'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$level   = if ($Elevated) { 'Highest' } else { 'Limited' }
$princ   = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $level
$set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'KvmShare' -Action $action -Trigger $trigger -Principal $princ -Settings $set -Force | Out-Null
Write-Host "Installed. Next: pair the machines (see README), then:  Start-ScheduledTask KvmShare"
Write-Host "CLI: $venv\Scripts\python.exe -m kvmshare status"
