#ifndef XOR_CRYPT_H
#define XOR_CRYPT_H

#include <windows.h>

#define XOR_KEY_LEN 32

// XOR encrypt/decrypt with rolling key.
// Key state advances per byte, so encrypt(decrypt(data)) = data.
// Same function for both directions.
void xor_rolling(PBYTE data, SIZE_T len, const BYTE key[XOR_KEY_LEN]);

#endif
