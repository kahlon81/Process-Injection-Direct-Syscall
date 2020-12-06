# Process-Injection-Direct-Syscall
Classic Process Injection but with direct syscalls

See https://pentester.blog/?p=761 (french)

Requirements :

- Windows 10 64 bits 1909
- Sublime Text 64 bits running
- testlib64.dll in C:\TEMP

Need a change in Syscalls.asm / NtCreateThreadEx10 and recompilation for different Windows 10 build (mov eax, 0bdh is for build 1909)




