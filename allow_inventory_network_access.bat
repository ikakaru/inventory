@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ruleName = 'Inventory Portal HTTP'; $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; if ($existing) { Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Profile Private -Direction Inbound -Action Allow | Out-Null; Write-Host 'Updated existing firewall rule.' } else { New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Private | Out-Null; Write-Host 'Created firewall rule for TCP port 80 on Private networks.' }"
echo.
echo Network access for Inventory is ready on private networks.
pause
