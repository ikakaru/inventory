@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ruleName = 'LRMDS Inventory Portal HTTP'; $legacyRuleName = 'Inventory Portal HTTP'; $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue; if (-not $existing) { $existing = Get-NetFirewallRule -DisplayName $legacyRuleName -ErrorAction SilentlyContinue }; if ($existing) { Set-NetFirewallRule -DisplayName $existing.DisplayName -Enabled True -Profile Private -Direction Inbound -Action Allow | Out-Null; Write-Host 'Updated existing firewall rule.' } else { New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Private | Out-Null; Write-Host 'Created firewall rule for TCP port 80 on Private networks.' }"
echo.
echo Network access for LRMDS Inventory is ready on private networks.
pause
