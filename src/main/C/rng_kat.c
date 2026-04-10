#include "rng.h"
#include "fips202.h"
#include <string.h>

static uint8_t seed[48];
static uint64_t ctr = 0;

void randombytes_init(uint8_t *entropy_input,
                      uint8_t *personalization_string,
                      int security_strength)
{
    (void)security_strength;

    for (int i = 0; i < 48; i++) {
        seed[i] = entropy_input[i % 32] ^
                  (personalization_string ? personalization_string[i % 32] : 0);
    }
    ctr = 0;
}

int randombytes(uint8_t *buf, size_t len)
{
    uint8_t in[56];
    memcpy(in, seed, 48);
    memcpy(in + 48, &ctr, 8);

    shake256(buf, len, in, 56);
    ctr++;

    return 0;
}