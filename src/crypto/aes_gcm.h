#ifndef AES_GCM_H
#define AES_GCM_H

#include <windows.h>

#define AES_GCM_KEY_LEN     32
#define AES_GCM_NONCE_LEN   12
#define AES_GCM_TAG_LEN     16
#define AES_GCM_PREFIX_LEN  3   // "v20" or "v10"
#define AES_GCM_OVERHEAD    (AES_GCM_PREFIX_LEN + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN)

// Decrypt a Chrome AES-256-GCM encrypted blob.
// blob layout: [3-byte prefix][12-byte nonce][ciphertext][16-byte tag]
// Returns allocated buffer with plaintext on success, NULL on failure.
// Caller must free() the returned buffer. *out_len receives plaintext length.
PBYTE aes_gcm_decrypt(const BYTE* blob, DWORD blob_len,
                      const BYTE key[AES_GCM_KEY_LEN], DWORD* out_len);

#endif
