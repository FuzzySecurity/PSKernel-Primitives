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
# Pointer can be converted as above
[IntPtr]$Pointer = [Kernel32]::VirtualAlloc([System.IntPtr]::Zero, $Bytes.Length, 0x3000, 0x40)
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
$Result += $Result
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

## Kernel Helper Functions

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

### Stage-BitmapReadWrite

Creates manager and worker bitmaps & leaks their kernel objects. This only works pre Win 10 v1607!

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

### Bitmap-Helpers

Just two small functions which act as a wrapper for GDI arbitrary r/w primitive.

```
# Read
PS C:\> Bitmap-Read -Address 0x41414141

# Write
PS C:\> Bitmap-Write -Address 0xFFFFF9010320F000 -Value 0xb33fb33fb33fb33f
```