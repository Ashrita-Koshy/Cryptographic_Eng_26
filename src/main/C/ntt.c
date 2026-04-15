#include "ntt.h"

void ntt(uint16_t *f) {
    size_t i = 1;
    uint32_t len, start, j;
    for (len = 128; len >= 2; len /= 2) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i++;
            for (j = start; j < start + len; j++) {
                int32_t t = (zeta * (int32_t)f[j + len]) % MLKEM_Q;
                f[j + len] = (uint16_t)(((int32_t)f[j] - t + MLKEM_Q) % MLKEM_Q);
                f[j] = (uint16_t)(((int32_t)f[j] + t) % MLKEM_Q);
            }
        }
    }
}

void nttInverse(uint16_t *f) {
    size_t i = 127;
    uint32_t len, start, j;
    for (len = 2; len <= 128; len *= 2) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i--;
            for (j = start; j < start + len; j++) {
                int32_t t = (int32_t)f[j];
                f[j] = (uint16_t)(((int32_t)f[j + len] + t) % MLKEM_Q);
                f[j + len] = (uint16_t)((zeta * ((int32_t)f[j + len] - t + MLKEM_Q)) % MLKEM_Q);
            }
        }
    }
    for (i = 0; i < MLKEM_N; i++) {
        f[i] = (uint16_t)(((int32_t)f[i] * 3303) % MLKEM_Q);
    }
}

void multiplyNTT(uint16_t *h, const uint16_t *f, const uint16_t *g) {
    uint16_t i;
    for (i = 0; i < 128; i++) {
        int32_t temp = ((int32_t)f[2*i + 1] * g[2*i + 1]) % MLKEM_Q;
        int32_t tz = (temp * zetaOddPowers[i]) % MLKEM_Q;
        if (tz < 0) tz += MLKEM_Q;
        h[2*i]     = (uint16_t)((((int32_t)f[2*i] * g[2*i]) % MLKEM_Q + tz) % MLKEM_Q);
        h[2*i + 1] = (uint16_t)(((((int32_t)f[2*i] * g[2*i + 1]) % MLKEM_Q) + (((int32_t)f[2*i + 1] * g[2*i]) % MLKEM_Q)) % MLKEM_Q);
    }
}
