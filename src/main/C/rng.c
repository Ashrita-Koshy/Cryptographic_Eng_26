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

// tiny-AES-c wrapper
// tiny-AES-c ecb works in-place, so copy in to out first
static void aes256_ecb(const uint8_t key[KEYLEN],
                       const uint8_t in[BLOCKLEN],
                       uint8_t       out[BLOCKLEN])
{
    struct AES_ctx ctx;

    // initialize aes context with the given key
    AES_init_ctx(&ctx, key);

    // copy input block first because tiny-AES-c encrypts in-place
    memcpy(out, in, BLOCKLEN);

    // encrypt one 16-byte block
    AES_ECB_encrypt(&ctx, out);

    // clear aes context
    memset(&ctx, 0, sizeof(ctx));
}

// collect entropy from clock jitter for now
// this is just for host-side testing
// later this part can be replaced with the board-side entropy source
static uint8_t jitter_one_byte(void)
{    
    uint8_t byte = 0;
    struct timespec t1, t2, resolution;
    clock_getres(CLOCK_MONOTONIC, &resolution); 
    clock_gettime(CLOCK_MONOTONIC, &t1);
    // build one byte by collecting 8 lsb values
    for (int bit = 0; bit < 8; bit++) {
        
        volatile unsigned int dummy = 0;

        // get first timestamp
        

        // add some small variable work in between
        for (volatile int j = 0; j < 500; j++)
            dummy ^= j;

        // get second timestamp
        clock_gettime(CLOCK_MONOTONIC, &t2);
        // use the lsb of the timing difference
        long delta = (t2.tv_nsec - t1.tv_nsec)/resolution.tv_nsec;
        byte |= ((uint8_t)(delta & 1)) << bit;
    }

    return byte;
}

static void collect_entropy(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t acc = 0;

        // oversample 4 times and xor them together
        for (int k = 0; k < 4; k++)
            acc ^= jitter_one_byte();
        buf[i] = acc;
    }
}

// increase v by 1 as a big-endian counter
static void increment_v(uint8_t v[BLOCKLEN])
{
    // start from the last byte and carry backward if needed
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

    // generate 48 bytes total using aes(key, v), aes(key, v+1), ...
    while (pos < SEEDLEN) {
        increment_v(ctx->v);
        aes256_ecb(ctx->key, ctx->v, tmp + pos);
        pos += BLOCKLEN;
    }

    // mix in provided_data with xor
    for (int i = 0; i < SEEDLEN; i++)
        tmp[i] ^= provided_data[i];
    // first 32 bytes become the new key
    memcpy(ctx->key, tmp, KEYLEN);

    // last 16 bytes become the new v
    memcpy(ctx->v, tmp + KEYLEN, BLOCKLEN);

    // clear temporary buffer
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

    // security_strength is kept for compatibility but not used here
    (void)security_strength;

    // start from all-zero key and v
    memset(drbg.key, 0, KEYLEN);
    memset(drbg.v,   0, BLOCKLEN);

    // use provided entropy if given
    if (entropy_input != NULL)
        memcpy(seed_material, entropy_input, SEEDLEN);
    else
        // otherwise collect host-side entropy for now
        collect_entropy(seed_material, SEEDLEN);

    // mix in personalization if provided
    if (personalization != NULL) {
        for (int i = 0; i < SEEDLEN; i++)
            seed_material[i] ^= personalization[i];
    }

    // initialize internal drbg state from seed material
    ctr_drbg_update(seed_material, &drbg);

    // mark drbg as initialized
    drbg.reseed_counter = 1;
    drbg_initialized = 1;

    // clear temporary seed buffer
    memset(seed_material, 0, sizeof(seed_material));
}

// generate random bytes
int randombytes(unsigned char *buf, unsigned long long len)
{
    // fail if output buffer is null
    if (buf == NULL)
        return -1;

    // fail if drbg has not been initialized yet
    if (!drbg_initialized)
        return -1;

    uint8_t block[BLOCKLEN];
    unsigned long long offset = 0;

    // keep generating 16-byte blocks until len is filled
    while (offset < len) {
        increment_v(drbg.v);
        aes256_ecb(drbg.key, drbg.v, block);

        // copy either a full block or the remaining bytes
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

    // count one more generate call
    drbg.reseed_counter++;

    // clear temporary block
    memset(block, 0, sizeof(block));
    return 0;
}
