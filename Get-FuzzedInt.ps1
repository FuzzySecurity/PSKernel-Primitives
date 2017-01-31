# [Byte] 1 or 0
function Return-Bool {
	$(Get-Random -Maximum 10000)%2
}

# -32768 to 32767
# 0xFFFF8000 to 0x7FFF
function Return-Int16 {
	$RandSwitch = $(Get-Random -Maximum 10000)%11
	switch ($RandSwitch) {
		0  {-32768}
		1  {32767}
		2  {-1}
		3  {1}
		4  {0}
		5  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		6  {0x100 -shl $(Get-Random -Maximum 10000)%6} # 0x100 -> 0x4000
		7  {$(Get-Random -Minimum -32768 -Maximum 32767)}
		8  {$(Get-Random -Minimum 0x7f00 -Maximum 0x7FFF)}
		9  {$(Get-Random -Minimum -32768 -Maximum -16384)}
		10 {$(Get-Random -Minimum -16384 -Maximum 0)}
	}
}

# -2147483648 to 2147483647
# 0x80000000 to 0x7FFFFFFF
function Return-Int32 {
	$RandSwitch = $(Get-Random -Maximum 10000)%14
	switch ($RandSwitch) {
		0  {-2147483648}
		1  {2147483647}
		2  {-1}
		3  {1}
		4  {0}
		5  {0x7fff0000}
		6  {0x7fffe000}
		7  {0x7fffffff - 0x1000}
		8  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		9  {0x100 -shl $(Get-Random -Maximum 10000)%19} # 0x100 -> 0x8000000
		10 {$(Get-Random -Minimum -2147483648 -Maximum 2147483647)}
		11 {$(Get-Random -Minimum 0x7f000000 -Maximum 0x7FFFFFFF)}
		12 {$(Get-Random -Minimum -2147483648 -Maximum -1073741824)}
		13 {$(Get-Random -Minimum -1073741824 -Maximum 0)}
	}
}

# -9223372036854775808 to 9223372036854775807
# 0x8000000000000000 to 0x7FFFFFFFFFFFFFFF
function Return-Int64 {
	$RandSwitch = $(Get-Random -Maximum 10000)%11
	switch ($RandSwitch) {
		0  {-9223372036854775808}
		1  {9223372036854775807}
		2  {-1}
		3  {1}
		4  {0}
		5  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		6  {0x100 -shl $(Get-Random -Maximum 10000)%23} # 0x100 -> 0x80000000
		7  {$(Get-Random -Minimum -9223372036854775808 -Maximum 9223372036854775807)}
		8  {$(Get-Random -Minimum 0x7f00000000000000 -Maximum 0x7FFFFFFFFFFFFFFF)}
		9  {$(Get-Random -Minimum -9223372036854775808 -Maximum -4611686018427387904)}
		10 {$(Get-Random -Minimum -4611686018427387904 -Maximum 0)}
	}
}

# 0 to 65535
# 0x0 to 0xFFFF
function Return-UInt16 {
	$RandSwitch = $(Get-Random -Maximum 10000)%9
	$FuzzInt = switch ($RandSwitch) {
		0  {65535}
		1  {0}
		2  {1}
		3  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		4  {0x100 -shl $(Get-Random -Maximum 10000)%7} # 0x100 -> 0x8000
		5  {0xF000 + (0xF -shl $(Get-Random -Maximum 10000)%8)} # 0xF000 -> 0xFF00
		6  {0xF000 + (0xFF -shl $(Get-Random -Maximum 10000)%4)} # 0xF000 -> 0xFFF0
		7  {$(Get-Random -Minimum 0 -Maximum 32767)}
		8  {$(Get-Random -Minimum 32767 -Maximum 65535)}
	} [UInt16]"0x$("{0:X}" -f $FuzzInt)"
}

# 0 to 4294967295
# 0x0 to 0xFFFFFFFF
function Return-UInt32 {
	$RandSwitch = $(Get-Random -Maximum 10000)%9
	$FuzzInt = switch ($RandSwitch) {
		0  {4294967295}
		1  {0}
		2  {1}
		3  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		4  {0x100 -shl $(Get-Random -Maximum 10000)%19} # 0x100 -> 0x8000000
		5  {0xFF000000 + (0xFF -shl $(Get-Random -Maximum 10000)%16)} # 0xFF000000 -> 0xFFFF0000
		6  {0xFF000000 + (0xFFFF -shl $(Get-Random -Maximum 10000)%8)} # 0xFF000000 -> 0xFFFFFF00
		7  {$(Get-Random -Minimum 0 -Maximum 2147483647)}
		8  {$(Get-Random -Minimum 2147483647 -Maximum 4294967295)}
	} [UInt32]"0x$("{0:X}" -f $FuzzInt)"
}

# 0 to 18446744073709551615
# 0x0 to 0xFFFFFFFFFFFFFFFF
function Return-UInt64 {
	$RandSwitch = $(Get-Random -Maximum 10000)%9
	$FuzzInt = switch ($RandSwitch) {
		0  {18446744073709551615}
		1  {0}
		2  {1}
		3  {8 -shl $(Get-Random -Maximum 10000)%9} # 8 -> 0x1000
		4  {0x100 -shl $(Get-Random -Maximum 10000)%19} # 0x100 -> 0x8000000
		5  {0xFFFF000000000000 + (0xFFFF -shl $(Get-Random -Maximum 10000)%16)} # 0xFFFF000000000000 -> 0xFFFEFFFFFFFF0000
		6  {0xFFFF000000000000 + (0xFFFFFF -shl $(Get-Random -Maximum 10000)%8)} # 0xFFFF000000000000 -> 0xFFFEFFFFFFFFFF00
		7  {$(Get-Random -Minimum 0 -Maximum 9223372036854775807)}
		8  {$(Get-Random -Minimum 9223372036854775807 -Maximum 18446744073709551615)}
	}
	if ($FuzzInt -Like "*E+*") {
		[Uint64]"$FuzzInt"
	} elseif ($FuzzInt -ge 10000000000000000000) {
		[Uint64]"0x$("{0:X}" -f [Uint64]$FuzzInt)"
	} else {
		[UInt64]"0x$("{0:X}" -f $FuzzInt)"
	}
}