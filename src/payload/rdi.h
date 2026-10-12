#ifndef RDI_H
#define RDI_H

#include <windows.h>

// Reflective loader: maps the PE from raw bytes, resolves imports,
// applies relocations, calls DllMain. Returns base address on success.
PVOID reflective_load(PBYTE raw_pe, DWORD pe_size);

// Wipe DOS + NT headers at the given base with random data.
void wipe_pe_headers(PVOID base);

#endif
