#include "ntt.h"

void ntt(uint16_t *f) {
    size_t i = 1;
    for (uint32_t len = 128; len >= 2; len /= 2) {
        for (uint32_t start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i++;
            for (uint32_t j = start; j < start + len; j++) {
                int32_t t = (zeta * (int32_t)f[j + len]) % MLKEM_Q;
                f[j + len] = (uint16_t)(((int32_t)f[j] - t + MLKEM_Q) % MLKEM_Q);
                f[j] = (uint16_t)(((int32_t)f[j] + t) % MLKEM_Q);
            }
        }
    }
}

void nttInverse(uint16_t *f) {
    size_t i = 127;
    for (uint32_t len = 2; len <= 128; len *= 2) {
        for (uint32_t start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i--;
            for (uint32_t j = start; j < start + len; j++) {
                int32_t t = (int32_t)f[j];
                f[j] = (uint16_t)(((int32_t)f[j + len] + t) % MLKEM_Q);
                f[j + len] = (uint16_t)((zeta * ((int32_t)f[j + len] - t + MLKEM_Q)) % MLKEM_Q);
            }
        }
    }
    for (size_t k = 0; k < MLKEM_N; k++) {
        f[k] = (uint16_t)(((int32_t)f[k] * 3303) % MLKEM_Q);
    }
}

void multiplyNTT(uint16_t *h, const uint16_t *f, const uint16_t *g) {
    for (uint16_t i = 0; i < 128; i++) {
        int32_t temp = ((int32_t)f[2*i + 1] * g[2*i + 1]) % MLKEM_Q;
        int32_t tz = (temp * zetaOddPowers[i]) % MLKEM_Q;
        if (tz < 0) tz += MLKEM_Q;
        h[2*i]     = (uint16_t)((((int32_t)f[2*i] * g[2*i]) % MLKEM_Q + tz) % MLKEM_Q);
        h[2*i + 1] = (uint16_t)(((((int32_t)f[2*i] * g[2*i + 1]) % MLKEM_Q) + (((int32_t)f[2*i + 1] * g[2*i]) % MLKEM_Q)) % MLKEM_Q);
    }
}
