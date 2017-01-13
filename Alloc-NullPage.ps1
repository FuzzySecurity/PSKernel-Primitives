function Alloc-NullPage {
<#
.SYNOPSIS
	Alloc null page for null pointer dereference vulnerabilities.
	Warning: Only Win7 32-bit!

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> $NullPage = Alloc-NullPage -Bytes 1024
	C:\PS> if ($NullPage -eq $true) {...}

#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$Bytes
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public static class Ntdll
	{
	    [DllImport("ntdll.dll")]
	    public static extern uint NtAllocateVirtualMemory(
	        IntPtr ProcessHandle,
	        ref IntPtr BaseAddress,
	        uint ZeroBits,
	        ref UInt32 AllocationSize,
	        UInt32 AllocationType,
	        UInt32 Protect);
	}
"@

	[IntPtr]$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
	[IntPtr]$BaseAddress = 0x1 # Rounded down to 0x00000000
	[UInt32]$AllocationSize = $Bytes
	$CallResult = [Ntdll]::NtAllocateVirtualMemory($ProcHandle, [ref]$BaseAddress, 0, [ref]$AllocationSize, 0x3000, 0x40)
	if ($CallResult -ne 0) {
	    $false
	} else {
	    $true
	}
}