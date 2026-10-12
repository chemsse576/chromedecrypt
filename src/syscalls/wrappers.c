#include "syscalls.h"

DWORD g_ssn;
PVOID g_gadget;

static SYSCALL_TABLE g_table;

extern NTSTATUS sc_gate(void);

BOOL sc_init_global(void) {
    return sc_init(&g_table);
}

#define GATE(name) \
    g_ssn = g_table.name.ssn; \
    g_gadget = g_table.name.gadget;

typedef NTSTATUS (*fn_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (*fn_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (*fn_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (*fn_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (*fn_NtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (*fn_NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (*fn_NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (*fn_NtClose)(HANDLE);
typedef NTSTATUS (*fn_NtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS (*fn_NtTerminateProcess)(HANDLE, NTSTATUS);
typedef NTSTATUS (*fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (*fn_NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);

NTSTATUS Sc_NtAllocateVirtualMemory(HANDLE ph, PVOID* ba, ULONG_PTR zb, PSIZE_T rs, ULONG at, ULONG pr) {
    GATE(NtAllocateVirtualMemory);
    return ((fn_NtAllocateVirtualMemory)sc_gate)(ph, ba, zb, rs, at, pr);
}

NTSTATUS Sc_NtWriteVirtualMemory(HANDLE ph, PVOID ba, PVOID buf, SIZE_T len, PSIZE_T written) {
    GATE(NtWriteVirtualMemory);
    return ((fn_NtWriteVirtualMemory)sc_gate)(ph, ba, buf, len, written);
}

NTSTATUS Sc_NtProtectVirtualMemory(HANDLE ph, PVOID* ba, PSIZE_T rs, ULONG np, PULONG op) {
    GATE(NtProtectVirtualMemory);
    return ((fn_NtProtectVirtualMemory)sc_gate)(ph, ba, rs, np, op);
}

NTSTATUS Sc_NtCreateThreadEx(PHANDLE th, ACCESS_MASK da, PVOID oa, HANDLE ph, PVOID sr, PVOID arg,
    ULONG cf, SIZE_T zb, SIZE_T ss, SIZE_T ms, PVOID al) {
    GATE(NtCreateThreadEx);
    return ((fn_NtCreateThreadEx)sc_gate)(th, da, oa, ph, sr, arg, cf, zb, ss, ms, al);
}

NTSTATUS Sc_NtQueueApcThread(HANDLE th, PVOID routine, PVOID a1, PVOID a2, PVOID a3) {
    GATE(NtQueueApcThread);
    return ((fn_NtQueueApcThread)sc_gate)(th, routine, a1, a2, a3);
}

NTSTATUS Sc_NtResumeThread(HANDLE th, PULONG prev) {
    GATE(NtResumeThread);
    return ((fn_NtResumeThread)sc_gate)(th, prev);
}

NTSTATUS Sc_NtWaitForSingleObject(HANDLE h, BOOLEAN alert, PLARGE_INTEGER timeout) {
    GATE(NtWaitForSingleObject);
    return ((fn_NtWaitForSingleObject)sc_gate)(h, alert, timeout);
}

NTSTATUS Sc_NtClose(HANDLE h) {
    GATE(NtClose);
    return ((fn_NtClose)sc_gate)(h);
}

NTSTATUS Sc_NtOpenProcess(PHANDLE ph, ACCESS_MASK da, PVOID oa, PVOID cid) {
    GATE(NtOpenProcess);
    return ((fn_NtOpenProcess)sc_gate)(ph, da, oa, cid);
}

NTSTATUS Sc_NtTerminateProcess(HANDLE ph, NTSTATUS code) {
    GATE(NtTerminateProcess);
    return ((fn_NtTerminateProcess)sc_gate)(ph, code);
}

NTSTATUS Sc_NtQueryInformationProcess(HANDLE ph, ULONG cls, PVOID info, ULONG len, PULONG ret) {
    GATE(NtQueryInformationProcess);
    return ((fn_NtQueryInformationProcess)sc_gate)(ph, cls, info, len, ret);
}

NTSTATUS Sc_NtFreeVirtualMemory(HANDLE ph, PVOID* ba, PSIZE_T rs, ULONG ft) {
    GATE(NtFreeVirtualMemory);
    return ((fn_NtFreeVirtualMemory)sc_gate)(ph, ba, rs, ft);
}
