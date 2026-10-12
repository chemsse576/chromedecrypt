#include "aes_gcm.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

PBYTE aes_gcm_decrypt(const BYTE* blob, DWORD blob_len,
                      const BYTE key[AES_GCM_KEY_LEN], DWORD* out_len) {
    if (blob_len <= AES_GCM_OVERHEAD)
        return NULL;

    const BYTE* nonce      = blob + AES_GCM_PREFIX_LEN;
    const BYTE* ciphertext = blob + AES_GCM_PREFIX_LEN + AES_GCM_NONCE_LEN;
    DWORD ct_len           = blob_len - AES_GCM_OVERHEAD;
    const BYTE* tag        = blob + blob_len - AES_GCM_TAG_LEN;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    PBYTE plaintext = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) goto cleanup;

    status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    status = BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
        (PUCHAR)key, AES_GCM_KEY_LEN, 0);
    if (status != 0) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce   = (PUCHAR)nonce;
    auth_info.cbNonce   = AES_GCM_NONCE_LEN;
    auth_info.pbTag     = (PUCHAR)tag;
    auth_info.cbTag     = AES_GCM_TAG_LEN;

    plaintext = (PBYTE)malloc(ct_len);
    if (!plaintext) goto cleanup;

    ULONG pt_len = 0;
    status = BCryptDecrypt(hkey, (PUCHAR)ciphertext, ct_len, &auth_info,
        NULL, 0, plaintext, ct_len, &pt_len, 0);
    if (status != 0) {
        free(plaintext);
        plaintext = NULL;
        goto cleanup;
    }

    *out_len = pt_len;

cleanup:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    return plaintext;
}
