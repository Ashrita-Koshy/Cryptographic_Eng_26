#include "ntt.h"
#include "auxiliary.h"

void ntt(uint16_t *f) {
    size_t i = 1;
    uint32_t len, start, j;

    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i++];            
            for (j = start; j < start + len; j++) {
                int32_t t = barrett_reduce(zeta * f[j + len]);
                int32_t a = f[j];
                int32_t b = t;

                f[j] = (uint16_t)barrett_reduce(a + b);
                f[j + len] = (uint16_t)barrett_reduce(a - b);
            }
        }
    }
}

void nttInverse(uint16_t *f) {
    size_t i = 127;
    uint32_t len, start, j;

    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i--];

            for (j = start; j < start + len; j++) {
                int32_t a = f[j];
                int32_t b = f[j + len];
                f[j] = (uint16_t)barrett_reduce(a + b);

                int32_t t = barrett_reduce(b - a);
                f[j + len] = (uint16_t)barrett_reduce(zeta * t);
            }
        }
    }

    // final multiplication by n^{-1} = 3303
    for (i = 0; i < MLKEM_N; i++) {
        f[i] = (uint16_t)barrett_reduce((int32_t)f[i] * 3303);
    }
}

void multiplyNTT(uint16_t *h, const uint16_t *f, const uint16_t *g) {
    uint16_t i;

    for (i = 0; i < 128; i++) {

        int32_t f0 = f[2*i];
        int32_t f1 = f[2*i + 1];
        int32_t g0 = g[2*i];
        int32_t g1 = g[2*i + 1];

        int32_t t1 = barrett_reduce(f1 * g1);
        int32_t tz = barrett_reduce(t1 * zetaOddPowers[i]);

        h[2*i] = (uint16_t)barrett_reduce(barrett_reduce(f0 * g0) + tz);

        int32_t t2 = barrett_reduce(f0 * g1);
        int32_t t3 = barrett_reduce(f1 * g0);

        h[2*i + 1] = (uint16_t)barrett_reduce(t2 + t3);
    }
}
