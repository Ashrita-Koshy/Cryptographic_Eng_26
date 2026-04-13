#ifndef RNG_H
#define RNG_H

#include <stdint.h>

// Initialize DRBG
// entropy_input: 48-byte seed
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization,
                      int            security_strength);

// Generate random bytes into buf
// Returns 0 on success
int randombytes(unsigned char *buf, unsigned long long len);

#endif // RNG_H