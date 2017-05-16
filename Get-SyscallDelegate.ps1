function Get-SyscallDelegate {
<#
.SYNOPSIS
	Allocate 32/64 bit shellcode and get a Syscall delegate for the memory pointer.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER ReturnType
	Syscall return type, this should be an NTSTATUS code (UInt32).

.PARAMETER ParameterArray
	An array of parameter types which the Syscall expects.

.EXAMPLE
	# Sample definition for NtWriteVirtualMemory
	C:\PS> $NtWriteVirtualMemory = Get-SyscallDelegate -ReturnType '[UInt32]' -ParameterArray @([IntPtr],[IntPtr],[IntPtr],[int],[ref][int])

	# Syscall ID = 0x37 (Win7)
	C:\PS> $NtWriteVirtualMemory.Invoke([UInt16]0x37,[IntPtr]$hProcess,[IntPtr]$pBaseAddress,[IntPtr]$pBuffer,$NumberOfBytesToWrite,[ref]$OutBytes)
#>

	param(
		[Parameter(Mandatory=$True)]
		[ValidateSet(
			'[Byte]',
			'[UInt16]',
			'[UInt32]',
			'[UInt64]',
			'[IntPtr]',
			'[String]')
		]
		$ReturnType,
		[Parameter(Mandatory=$True)]
		[AllowEmptyCollection()]
		[Object[]]$ParameterArray
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public class Syscall
	{
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
	}
"@

	#-----------------------------
	# -= Arch x86 =-
	# ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall.asm
	# Compiled with Get-KeystoneAssembly => https://github.com/keystone-engine/keystone/tree/master/bindings/powershell
	#-----------------------------
	$x86SyscallStub = [Byte[]] @(
	0x55,                                # push ebp
	0x89, 0xE5,                          # mov ebp, esp
	0x81, 0xEC, 0x84, 0x00, 0x00, 0x00,  # sub esp, 84h
	0x8B, 0x8D, 0x88, 0x00, 0x00, 0x00,  # mov ecx, [ebp + 88h]
	0x51,                                # push ecx
	0x8B, 0x8D, 0x84, 0x00, 0x00, 0x00,  # mov ecx, [ebp + 84h]
	0x51,                                # push ecx
	0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00,  # mov ecx, [ebp + 80h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x7C,                    # mov ecx, [ebp + 7Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x78,                    # mov ecx, [ebp + 78h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x74,                    # mov ecx, [ebp + 74h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x70,                    # mov ecx, [ebp + 70h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x6C,                    # mov ecx, [ebp + 6Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x68,                    # mov ecx, [ebp + 68h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x64,                    # mov ecx, [ebp + 64h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x60,                    # mov ecx, [ebp + 60h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x5C,                    # mov ecx, [ebp + 5Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x58,                    # mov ecx, [ebp + 58h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x54,                    # mov ecx, [ebp + 54h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x50,                    # mov ecx, [ebp + 50h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x4C,                    # mov ecx, [ebp + 4Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x48,                    # mov ecx, [ebp + 48h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x44,                    # mov ecx, [ebp + 44h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x40,                    # mov ecx, [ebp + 40h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x3C,                    # mov ecx, [ebp + 3Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x38,                    # mov ecx, [ebp + 38h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x34,                    # mov ecx, [ebp + 34h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x30,                    # mov ecx, [ebp + 30h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x2C,                    # mov ecx, [ebp + 2Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x28,                    # mov ecx, [ebp + 28h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x24,                    # mov ecx, [ebp + 24h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x20,                    # mov ecx, [ebp + 20h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x1C,                    # mov ecx, [ebp + 1Ch]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x18,                    # mov ecx, [ebp + 18h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x14,                    # mov ecx, [ebp + 14h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x10,                    # mov ecx, [ebp + 10h]
	0x51,                                # push ecx
	0x8B, 0x4D, 0x0C,                    # mov ecx, [ebp + 0Ch]
	0x51,                                # push ecx
	0x8B, 0x45, 0x08,                    # mov eax, [ebp + 08h]
	0xBA, 0x00, 0x03, 0xFE, 0x7F,        # mov edx, 7FFE0300h
	0xFF, 0x12,                          # call dword ptr [edx]
	0x89, 0xEC,                          # mov esp, ebp
	0x5D,                                # pop ebp
	0xC3)                                # ret
	
	#-----------------------------
	# -= Arch x64 =-
	# ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall_x64.asm
	# Compiled with Get-KeystoneAssembly => https://github.com/keystone-engine/keystone/tree/master/bindings/powershell
	#-----------------------------
	$x64SyscallStub = [Byte[]] @(
	0x55,                                      # push rbp
	0x48, 0x89, 0xE5,                          # mov rbp, rsp
	0x48, 0x81, 0xEC, 0x18, 0x01, 0x00, 0x00,  # sub rsp, 118h
	0x48, 0x89, 0xC8,                          # mov rax, rcx
	0x49, 0x89, 0xD2,                          # mov r10, rdx
	0x4C, 0x89, 0xC2,                          # mov rdx, r8
	0x4D, 0x89, 0xC8,                          # mov r8, r9
	0x48, 0x8B, 0x8D, 0x10, 0x01, 0x00, 0x00,  # mov rcx, [rbp + 110h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x08, 0x01, 0x00, 0x00,  # mov rcx, [rbp + 108h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x00, 0x01, 0x00, 0x00,  # mov rcx, [rbp + 100h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xF8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0F8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xF0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0F0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xE8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0E8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xE0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0E0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xD8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0D8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xD0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0D0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xC8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0C8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xC0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0C0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xB8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0B8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xB0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0B0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xA8, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0A8h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0xA0, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 0A0h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x98, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 98h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x90, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 90h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x88, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 88h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00,  # mov rcx, [rbp + 80h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x78,                    # mov rcx, [rbp + 78h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x70,                    # mov rcx, [rbp + 70h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x68,                    # mov rcx, [rbp + 68h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x60,                    # mov rcx, [rbp + 60h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x58,                    # mov rcx, [rbp + 58h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x50,                    # mov rcx, [rbp + 50h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x48,                    # mov rcx, [rbp + 48h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x40,                    # mov rcx, [rbp + 40h]
	0x51,                                      # push rcx
	0x48, 0x8B, 0x4D, 0x38,                    # mov rcx, [rbp + 38h]
	0x51,                                      # push rcx
	0x4C, 0x8B, 0x4D, 0x30,                    # mov r9, [rbp + 30h]
	0x4C, 0x89, 0xD1,                          # mov rcx, r10
	0x0F, 0x05,                                # syscall
	0x48, 0x89, 0xEC,                          # mov rsp, rbp
	0x5D,                                      # pop rbp
	0xC3)                                      # ret

	if (!$SyscallStubPointer) {
		# Alloc relevant syscall stub
		if ([System.IntPtr]::Size -eq 4) {
			[IntPtr]$Script:SyscallStubPointer = [Syscall]::VirtualAlloc([System.IntPtr]::Zero, $x86SyscallStub.Length, 0x3000, 0x40)
			[System.Runtime.InteropServices.Marshal]::Copy($x86SyscallStub, 0, $SyscallStubPointer, $x86SyscallStub.Length)
		} else {
			[IntPtr]$Script:SyscallStubPointer = [Syscall]::VirtualAlloc([System.IntPtr]::Zero, $x64SyscallStub.Length, 0x3000, 0x40)
			[System.Runtime.InteropServices.Marshal]::Copy($x64SyscallStub, 0, $SyscallStubPointer, $x64SyscallStub.Length)
		}
	}

	# Courtesy of @mattifestation
	# => http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
	Function Get-DelegateType
	{
		Param
		(
			[OutputType([Type])]
			[Parameter( Position = 0)]
			[Type[]]
			$Parameters = (New-Object Type[](0)),
			[Parameter( Position = 1 )]
			[Type]
			$ReturnType = [Void]
		)
	
		$Domain = [AppDomain]::CurrentDomain
		$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
		$TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
		$ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
		$ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
		$MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
		$MethodBuilder.SetImplementationFlags('Runtime, Managed')
		
		Write-Output $TypeBuilder.CreateType()
	}

	# Prepare delegate
	if ($ParameterArray) {
		$ParamCount = $ParameterArray.Length
		$ParamList = [String]::Empty
		for ($i=0;$i-lt$ParamCount;$i++) {
			if ($ParameterArray[$i].Value) {
				$ParamList += "[" + $ParameterArray[$i].Value.Name + "].MakeByRefType(), "
			} else {
				$ParamList += "[" + $ParameterArray[$i].Name + "], "
			}
		}
		$ParamList = ($ParamList.Substring(0,$ParamList.Length-2)).Insert(0,", ")
	}
	$IEXBootstrap = "Get-DelegateType @([UInt16] $ParamList) ($ReturnType)"
	$SyscallDelegate = IEX $IEXBootstrap
	[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SyscallStubPointer, $SyscallDelegate)
}