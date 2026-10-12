#ifndef SHELLCODE_H
#define SHELLCODE_H

#include <windows.h>

// Build a position-independent x64 shellcode that:
//   1. Calls LoadLibraryA(dll_path)
//   2. Calls GetProcAddress(hMod, "payload_main")
//   3. Calls payload_main(0)
//   4. Returns
//
// dll_path: null-terminated path to the DLL on disk
// out_size: receives total shellcode size
// Returns: allocated shellcode buffer (caller frees)
PBYTE build_loader_shellcode(const char* dll_path, DWORD* out_size);

#endif
