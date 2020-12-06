# Process-Injection-Direct-Syscall
Classic Process Injection but with direct syscalls

See https://pentester.blog/?p=761 (french)

Requirements :

- Windows 10 64 bits 1909
- Sublime Text 64 bits running
- testlib64.dll in C:\TEMP

Need a change in Syscalls.asm and recompilation for different Windows 10 build

Syscalls.asm, here 	mov eax, 0bdh is for build 1909

; NtCreateThreadEx10
; Windows 10
; 1507		 1511		 1607		 1703		 1709		 1803		 1809		 1903		 1909		 2004		20H2
; 0x00b3 	 0x00b4 	 0x00b6 	 0x00b9 	 0x00ba 	 0x00bb 	 0x00bc 	 0x00bd 	 0x00bd 	 0x00c1 	 0x00c1

NtCreateThreadEx10 proc
		mov r10, rcx
		mov eax, 0bdh
		syscall
		ret
NtCreateThreadEx10 endp

