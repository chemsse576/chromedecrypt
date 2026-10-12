#include "xor_crypt.h"

void xor_rolling(PBYTE data, SIZE_T len, const BYTE key[XOR_KEY_LEN]) {
    BYTE state[XOR_KEY_LEN];
    memcpy(state, key, XOR_KEY_LEN);

    for (SIZE_T i = 0; i < len; i++) {
        BYTE k = state[i % XOR_KEY_LEN];
        data[i] ^= k;
        // Roll the key: feed ciphertext byte back into state
        state[i % XOR_KEY_LEN] = (BYTE)((k + data[i] + (BYTE)(i & 0xFF)) & 0xFF);
    }
}
