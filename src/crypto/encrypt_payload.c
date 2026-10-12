// Standalone tool: encrypt a DLL with XOR rolling key
// Usage: encrypt_payload <input.dll> <output.bin>
// Produces: "XORPLD" + 32-byte key + encrypted data

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include "xor_crypt.h"

#pragma comment(lib, "bcrypt.lib")

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input.dll> <output.bin>\n", argv[0]);
        return 1;
    }

    FILE* fin = fopen(argv[1], "rb");
    if (!fin) { printf("Cannot open %s\n", argv[1]); return 1; }
    fseek(fin, 0, SEEK_END);
    long size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    BYTE* data = (BYTE*)malloc(size);
    fread(data, 1, size, fin);
    fclose(fin);

    // Generate random key
    BYTE key[XOR_KEY_LEN];
    BCryptGenRandom(NULL, key, XOR_KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Encrypt
    xor_rolling(data, size, key);

    // Write output: marker + key + encrypted data
    FILE* fout = fopen(argv[2], "wb");
    if (!fout) { printf("Cannot create %s\n", argv[2]); free(data); return 1; }
    fwrite("XORPLD", 1, 6, fout);
    fwrite(key, 1, XOR_KEY_LEN, fout);
    fwrite(data, 1, size, fout);
    fclose(fout);

    printf("[+] Encrypted %ld bytes -> %s\n", size, argv[2]);

    SecureZeroMemory(key, XOR_KEY_LEN);
    free(data);
    return 0;
}
