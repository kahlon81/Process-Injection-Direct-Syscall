# Process-Injection-Direct-Syscall
Classic Process Injection but with direct syscalls

See https://pentester.blog/?p=761 (french)

Requirements :

- Windows 10 64 bits 1909
- Sublime Text 64 bits running
- testlib64.dll in C:\TEMP

Need a change in NtCreateThreadEx10 function (Syscalls.asm) and recompilation if Windows 10 build is not 1909 (mov eax, 0bdh is specific for build 1909)

See https://j00ru.vexillium.org/syscalls/nt/64/ for required values.




