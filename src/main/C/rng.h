#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stddef.h>

void randombytes_init(uint8_t *entropy_input,
                      uint8_t *personalization_string,
                      int security_strength);
int randombytes(uint8_t *buf, size_t len);

#endif /* RNG_H */