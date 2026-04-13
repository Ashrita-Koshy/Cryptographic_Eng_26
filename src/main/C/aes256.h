#ifndef AES256_H
#define AES256_H

#include <stdint.h>

// encrypt one 16-byte block using aes-256 ecb
// key: 32 bytes
// plaintext: 16 bytes
// ciphertext: 16 bytes output
void aes256_ecb_encrypt(const uint8_t key[32],
                        const uint8_t plaintext[16],
                        uint8_t       ciphertext[16]);

#endif // AES256_H