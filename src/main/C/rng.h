#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stddef.h>

int randombytes(uint8_t *buf, size_t len);

#endif /* RNG_H */