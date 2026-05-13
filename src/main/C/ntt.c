#include "ntt.h"

void ntt(uint16_t *f) {
    size_t i = 1;
    uint32_t len, start, j;
    for (len = 128; len >= 2; len /= 2) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            uint16_t zeta = zetaPowersNew[i];
            i++;
            for (j = start; j < start + len; j++) {
                uint16_t t_new = mult_q(zeta,f[j + len]);
                int16_t diff = (int16_t) f[j] - t_new;
                f[j + len] = (diff < 0) ? diff + MLKEM_Q : diff;
                f[j] = f[j] + t_new;
                if(f[j] >= MLKEM_Q){
                    f[j] -= MLKEM_Q;
                }
            }
        }
    }
}

void nttInverse(uint16_t *f) {
    size_t i = 127;
    uint32_t len, start, j;
    for (len = 2; len <= 128; len *= 2) {
        for (start = 0; start < MLKEM_N; start += 2 * len) {
            uint16_t zeta = zetaPowersNew[i];
            i--;
            for (j = start; j < start + len; j++) {
                uint16_t t = f[j];
                f[j] = f[j + len] + t;
                if(f[j] >= MLKEM_Q){
                    f[j] -= MLKEM_Q;
                }
                int16_t diff = f[j + len] - t;
                diff = (diff < 0) ? (diff + MLKEM_Q) : diff;
                f[j + len] = mult_q(zeta,diff);
            }
        }
    }
    for (i = 0; i < MLKEM_N; i++) {
        f[i] = mult_q(f[i],512);
    }
}

void multiplyNTT(uint16_t *h, const uint16_t *f, const uint16_t *g) {
    uint16_t i;
    for (i = 0; i < 128; i++) {
        int32_t temp = mult_q(reduce_q((uint32_t)f[2*i + 1]*g[2*i + 1]),zetaOddPowersNew[i]);
        temp = reduce_q((uint32_t)f[2*i]*g[2*i]) + temp;
        if (temp >= MLKEM_Q) temp -= MLKEM_Q;
        h[2*i] = temp;
        temp = reduce_q((uint32_t)f[2*i]*g[2*i + 1]) + reduce_q((uint32_t)f[2*i + 1]*g[2*i]);
        if (temp >= MLKEM_Q) temp -= MLKEM_Q;
        h[2*i + 1] = temp;
    }
}
