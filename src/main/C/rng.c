#include "rng.h"
#include "aes256.h"
#include <string.h>

// NIST SP 800-90A CTR_DRBG using AES-256
// seed length = key(32) + v(16) = 48 bytes

#define AES256_KEYLEN   32
#define AES256_BLOCKLEN 16
#define CTR_DRBG_SEEDLEN (AES256_KEYLEN + AES256_BLOCKLEN)  // 48

typedef struct {
    uint8_t key[AES256_KEYLEN];
    uint8_t v[AES256_BLOCKLEN];
    int     reseed_counter;
} CTR_DRBG_STATE;

static CTR_DRBG_STATE drbg_ctx;

// increase v by 1 as a big-endian counter
static void increment_v(uint8_t v[AES256_BLOCKLEN])
{
    for (int i = AES256_BLOCKLEN - 1; i >= 0; i--) {
        if (++v[i] != 0)
            break;
    }
}

// ctr_drbg_update from sp 800-90a
// makes new key and new v from current state + provided_data
static void ctr_drbg_update(const uint8_t provided_data[CTR_DRBG_SEEDLEN],
                            CTR_DRBG_STATE *ctx)
{
    uint8_t tmp[CTR_DRBG_SEEDLEN];
    int pos = 0;

    // keep encrypting incremented v until tmp is filled
    while (pos < CTR_DRBG_SEEDLEN) {
        increment_v(ctx->v);
        aes256_ecb_encrypt(ctx->key, ctx->v, tmp + pos);
        pos += AES256_BLOCKLEN;
    }

    // mix in provided_data
    for (int i = 0; i < CTR_DRBG_SEEDLEN; i++)
        tmp[i] ^= provided_data[i];

    // first 32 bytes become new key
    memcpy(ctx->key, tmp, AES256_KEYLEN);

    // last 16 bytes become new v
    memcpy(ctx->v, tmp + AES256_KEYLEN, AES256_BLOCKLEN);

    memset(tmp, 0, sizeof(tmp));
}

// initialize DRBG
// entropy_input should give 48 bytes
// getting 48 bytes entropy_input from the board's TRNG later
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization,
                      int            security_strength)
{
    uint8_t seed_material[CTR_DRBG_SEEDLEN];

    (void)security_strength;

    // start from all-zero key and v
    memset(drbg_ctx.key, 0, AES256_KEYLEN);
    memset(drbg_ctx.v,   0, AES256_BLOCKLEN);

    // seed_material starts from entropy_input
    memcpy(seed_material, entropy_input, CTR_DRBG_SEEDLEN);

    // if personalization exists, mix it in with xor
    if (personalization != NULL) {
        for (int i = 0; i < CTR_DRBG_SEEDLEN; i++)
            seed_material[i] ^= personalization[i];
    }

    // update internal state using seed_material
    ctr_drbg_update(seed_material, &drbg_ctx);
    drbg_ctx.reseed_counter = 1;

    memset(seed_material, 0, sizeof(seed_material));
}

// generate random bytes
int randombytes(unsigned char *buf, unsigned long long len)
{
    uint8_t block[AES256_BLOCKLEN];
    unsigned long long offset = 0;

    // keep generating 16-byte aes blocks until requested length is filled
    while (offset < len) {
        increment_v(drbg_ctx.v);
        aes256_ecb_encrypt(drbg_ctx.key, drbg_ctx.v, block);

        unsigned long long chunk = len - offset;
        if (chunk > AES256_BLOCKLEN)
            chunk = AES256_BLOCKLEN;

        memcpy(buf + offset, block, (size_t)chunk);
        offset += chunk;
    }

    // update state after output
    // this is for backtracking resistance
    uint8_t zeroes[CTR_DRBG_SEEDLEN];
    memset(zeroes, 0, CTR_DRBG_SEEDLEN);
    ctr_drbg_update(zeroes, &drbg_ctx);

    drbg_ctx.reseed_counter++;

    memset(block, 0, sizeof(block));
    return 0;
}