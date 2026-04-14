#include "rng.h"
#include "aes.h"
#include <string.h>
#include <stdint.h>
#include <time.h>


#define KEYLEN   32
#define BLOCKLEN 16
#define SEEDLEN  (KEYLEN + BLOCKLEN)   // 48

// drbg internal state
typedef struct {
    uint8_t key[KEYLEN];
    uint8_t v[BLOCKLEN];
    int     reseed_counter;
} CTR_DRBG_STATE;

static CTR_DRBG_STATE drbg;
static int drbg_initialized = 0;

// tiny-aes-c wrapper
// tiny-aes-c ecb works in-place, so copy in to out first
static void aes256_ecb(const uint8_t key[KEYLEN],
                       const uint8_t in[BLOCKLEN],
                       uint8_t       out[BLOCKLEN])
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    memcpy(out, in, BLOCKLEN);
    AES_ECB_encrypt(&ctx, out);
    memset(&ctx, 0, sizeof(ctx));
}

// collect entropy from clock jitter for now
// this is just for host-side testing
// later this part can be replaced with the board-side entropy source
static uint8_t jitter_one_byte(void)
{
    uint8_t byte = 0;

    for (int bit = 0; bit < 8; bit++) {
        struct timespec t1, t2;
        volatile unsigned int dummy = 0;

        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (volatile int j = 0; j < 500; j++)
            dummy ^= j;
        clock_gettime(CLOCK_MONOTONIC, &t2);

        long delta = t2.tv_nsec - t1.tv_nsec;
        byte |= ((uint8_t)(delta & 1)) << bit;
    }
    return byte;
}

static void collect_entropy(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t acc = 0;
        for (int k = 0; k < 4; k++)
            acc ^= jitter_one_byte();
        buf[i] = acc;
    }
}

// increase v by 1 as a big-endian counter
static void increment_v(uint8_t v[BLOCKLEN])
{
    for (int i = BLOCKLEN - 1; i >= 0; i--) {
        if (++v[i] != 0)
            break;
    }
}

// ctr_drbg update
// makes new key and new v from current state + provided_data
static void ctr_drbg_update(const uint8_t provided_data[SEEDLEN],
                            CTR_DRBG_STATE *ctx)
{
    uint8_t tmp[SEEDLEN];
    int pos = 0;

    while (pos < SEEDLEN) {
        increment_v(ctx->v);
        aes256_ecb(ctx->key, ctx->v, tmp + pos);
        pos += BLOCKLEN;
    }

    for (int i = 0; i < SEEDLEN; i++)
        tmp[i] ^= provided_data[i];

    memcpy(ctx->key, tmp, KEYLEN);
    memcpy(ctx->v,   tmp + KEYLEN, BLOCKLEN);
    memset(tmp, 0, sizeof(tmp));
}

// initialize drbg
// if entropy_input is null, collect entropy here for now
// entropy_input must point to at least 48 bytes if it is not null
// personalization must also point to at least 48 bytes if it is used
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization,
                      int            security_strength)
{
    uint8_t seed_material[SEEDLEN];

    (void)security_strength;

    memset(drbg.key, 0, KEYLEN);
    memset(drbg.v,   0, BLOCKLEN);

    if (entropy_input != NULL)
        memcpy(seed_material, entropy_input, SEEDLEN);
    else
        collect_entropy(seed_material, SEEDLEN);

    if (personalization != NULL) {
        for (int i = 0; i < SEEDLEN; i++)
            seed_material[i] ^= personalization[i];
    }

    ctr_drbg_update(seed_material, &drbg);
    drbg.reseed_counter = 1;
    drbg_initialized = 1;

    memset(seed_material, 0, sizeof(seed_material));
}

// generate random bytes
int randombytes(unsigned char *buf, unsigned long long len)
{
    if (buf == NULL)
        return -1;

    if (!drbg_initialized)
        return -1;

    uint8_t block[BLOCKLEN];
    unsigned long long offset = 0;

    while (offset < len) {
        increment_v(drbg.v);
        aes256_ecb(drbg.key, drbg.v, block);

        unsigned long long chunk = len - offset;
        if (chunk > BLOCKLEN)
            chunk = BLOCKLEN;

        memcpy(buf + offset, block, (size_t)chunk);
        offset += chunk;
    }

    // update state after output for backtracking resistance
    uint8_t zeroes[SEEDLEN];
    memset(zeroes, 0, SEEDLEN);
    ctr_drbg_update(zeroes, &drbg);

    drbg.reseed_counter++;
    memset(block, 0, sizeof(block));
    return 0;
}