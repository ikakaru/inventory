@echo off
setlocal
set "PYTHON=C:\Users\erdse\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
set "INVENTORY_PORTAL_HOST=0.0.0.0"
set "INVENTORY_PORTAL_PORT=80"
title LRMDS Inventory LAN Server
echo.
echo Starting LRMDS Inventory for LAN access...
echo If other computers cannot connect, run allow_inventory_network_access.bat as Administrator once.
"%PYTHON%" "%~dp0portal_server.py"
