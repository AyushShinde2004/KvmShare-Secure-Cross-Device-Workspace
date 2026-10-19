Unregister-ScheduledTask -TaskName 'KvmShare' -Confirm:$false -ErrorAction SilentlyContinue
Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-Command',"Remove-NetFirewallRule -DisplayName 'KvmShare*' -ErrorAction SilentlyContinue"
Write-Host "Removed task and firewall rules. Keys/pairings/logs remain in $env:LOCALAPPDATA\KvmShare - delete that folder to forget all pairings."
