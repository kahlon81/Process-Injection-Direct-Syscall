#pragma once

#include <Windows.h>

#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
typedef LONG KPRIORITY;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _WIN_VER_INFO {
	WCHAR chOSMajorMinor[8];
	DWORD dwBuildNumber;
	UNICODE_STRING ProcName;
	HANDLE hTargetPID;
	LPCSTR lpApiCall;
	INT SystemCall;
} WIN_VER_INFO, *PWIN_VER_INFO;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*
NtCreateThreadEx
*/

// Here is the prototype of NtCreateThreadEx function [undocumented]
typedef NTSTATUS(WINAPI* LPFN_NTCREATETHREADEX)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE ThreadProcedure,
	IN LPVOID ParameterData,
	IN BOOL CreateSuspended,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT LPVOID BytesBuffer);

// Windows 7 SP1 / Server 2008 R2 specific Syscalls
EXTERN_C NTSTATUS NtAllocateVirtualMemory7SP1(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtFreeVirtualMemory7SP1(HANDLE ProcessHandle, PVOID *BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS ZwOpenProcess7SP1(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS ZwClose7SP1(IN HANDLE KeyHandle);
EXTERN_C NTSTATUS ZwWriteVirtualMemory7SP1(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwProtectVirtualMemory7SP1(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation7SP1(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtCreateFile7SP1(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

// Windows 8 / Server 2012 specific Syscalls
EXTERN_C NTSTATUS NtAllocateVirtualMemory80(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtFreeVirtualMemory80(HANDLE ProcessHandle, PVOID *BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS ZwOpenProcess80(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS ZwClose80(IN HANDLE KeyHandle);
EXTERN_C NTSTATUS ZwWriteVirtualMemory80(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwProtectVirtualMemory80(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation80(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtCreateFile80(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);


// Windows 8.1 / Server 2012 R2 specific Syscalls
EXTERN_C NTSTATUS NtAllocateVirtualMemory81(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtFreeVirtualMemory81(HANDLE ProcessHandle, PVOID *BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS ZwOpenProcess81(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS ZwClose81(IN HANDLE KeyHandle);
EXTERN_C NTSTATUS ZwWriteVirtualMemory81(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwProtectVirtualMemory81(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation81(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtCreateFile81(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);


// Windows 10 / Server 2016 specific Syscalls
EXTERN_C NTSTATUS NtAllocateVirtualMemory10(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtFreeVirtualMemory10(HANDLE ProcessHandle, PVOID *BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS ZwOpenProcess10(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS ZwClose10(IN HANDLE KeyHandle);
EXTERN_C NTSTATUS ZwWriteVirtualMemory10(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwProtectVirtualMemory10(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation10(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtCreateFile10(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtCreateThreadEx10(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
	IN PVOID Argument,
	IN ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList
);

NTSTATUS (*NtCreateThreadEx) (
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
	PVOID Argument,
	ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList
);

NTSTATUS(*NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

NTSTATUS(*NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	IN OUT PSIZE_T RegionSize,
	ULONG FreeType
	);

NTSTATUS(*ZwOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

NTSTATUS(WINAPI *ZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

NTSTATUS(*ZwWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
	);

NTSTATUS(*ZwProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*NtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);

NTSTATUS(*ZwClose)(
	IN HANDLE KeyHandle
	);

typedef NTSTATUS(NTAPI *_RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSYSAPI BOOLEAN(NTAPI *_RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);
