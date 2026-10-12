#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// NTSTATUS may already be typedef'd by winternl.h — guard it
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif
#define STATUS_SUCCESS ((NTSTATUS)0)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define DJB2_SEED 5381

typedef struct _SYSCALL_ENTRY {
    DWORD   ssn;
    PVOID   gadget;     // ptr to syscall;ret in ntdll
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtQueueApcThread;
    SYSCALL_ENTRY NtResumeThread;
    SYSCALL_ENTRY NtWaitForSingleObject;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtOpenProcess;
    SYSCALL_ENTRY NtTerminateProcess;
    SYSCALL_ENTRY NtQueryInformationProcess;
    SYSCALL_ENTRY NtFreeVirtualMemory;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

// djb2 hash (compile-time capable)
static inline DWORD djb2_hash(const char* str) {
    DWORD h = DJB2_SEED;
    while (*str)
        h = ((h << 5) + h) + (unsigned char)*str++;
    return h;
}

// Pre-computed hashes for target Nt* functions
#define H_NtAllocateVirtualMemory       0x6793C34C
#define H_NtWriteVirtualMemory          0x95F3A792
#define H_NtProtectVirtualMemory        0x082962C8
#define H_NtCreateThreadEx              0xCB0C2130
#define H_NtQueueApcThread              0xD4612238
#define H_NtResumeThread                0x2C7B3D30
#define H_NtWaitForSingleObject         0x4C6DC63C
#define H_NtClose                       0x8B8E133D
#define H_NtOpenProcess                 0x5003C058
#define H_NtTerminateProcess            0x1703AB2F
#define H_NtQueryInformationProcess     0xD034FC62
#define H_NtFreeVirtualMemory           0x471AA7E9

// Initialize the syscall table by walking ntdll exports (Halo's Gate)
BOOL sc_init(PSYSCALL_TABLE table);

// Initialize the global syscall table (calls sc_init internally)
BOOL sc_init_global(void);

// Typed wrappers (implemented in wrappers.c, use sc_gate from stub.asm)
NTSTATUS Sc_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS Sc_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS Sc_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS Sc_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
    SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList);

NTSTATUS Sc_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

NTSTATUS Sc_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

NTSTATUS Sc_NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS Sc_NtClose(HANDLE Handle);

NTSTATUS Sc_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId);

NTSTATUS Sc_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSTATUS Sc_NtQueryInformationProcess(HANDLE ProcessHandle,
    ULONG ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength);

NTSTATUS Sc_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

#endif
