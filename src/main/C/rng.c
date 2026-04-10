// #include "rng.h"

// // depends on platform, it will use cryptographically secure RNG functions 
// // on Windows, macOS, Linux, or fallback to /dev/urandom on UNIX-like systems.
// #if defined(_WIN32) || defined(_WIN64)
//   #define RB_PLATFORM_WINDOWS
// #elif defined(__APPLE__) && defined(__MACH__)
//   #define RB_PLATFORM_APPLE
// #elif defined(__linux__)
//   #define RB_PLATFORM_LINUX
// #else
//   #define RB_PLATFORM_FALLBACK          
// #endif

// // Windows: BCryptGenRandom 
// #ifdef RB_PLATFORM_WINDOWS

// #include <windows.h>
// #include <bcrypt.h>          //bcrypt.lib
// #pragma comment(lib, "bcrypt.lib")

// int randombytes(uint8_t *buf, size_t len)
// {
//     if (buf == NULL || len == 0) return 0;

//     NTSTATUS status = BCryptGenRandom(
//         NULL,                           
//         (PUCHAR)buf,
//         (ULONG)len,
//         BCRYPT_USE_SYSTEM_PREFERRED_RNG 
//     );
//     return (status >= 0) ? 0 : -1;   
// }

// //macOS, iOS: arc4random_buf
// #elif defined(RB_PLATFORM_APPLE)

// #include <stdlib.h>           

// int randombytes(uint8_t *buf, size_t len)
// {
//     if (buf == NULL || len == 0) return 0;
//     arc4random_buf(buf, len);           
//     return 0;
// }

// //Linux: getrandom(2) syscall (glibc ≥ 2.25, kernel ≥ 3.17)
// #elif defined(RB_PLATFORM_LINUX)

// #include <errno.h>
// #include <sys/random.h>       

// int randombytes(uint8_t *buf, size_t len)
// {
//     if (buf == NULL || len == 0) return 0;

//     size_t offset = 0;
//     while (offset < len) {
//         ssize_t ret = getrandom(buf + offset, len - offset, 0);
//         if (ret < 0) {
//             if (errno == EINTR) continue;   
//             return -1;                      
//         }
//         offset += (size_t)ret;
//     }
//     return 0;
// }

// // UNIX: /dev/urandom fallback
// #else

// #include <stdio.h>

// int randombytes(uint8_t *buf, size_t len)
// {
//     if (buf == NULL || len == 0) return 0;

//     FILE *f = fopen("/dev/urandom", "rb");
//     if (f == NULL) return -1;

//     size_t rd = fread(buf, 1, len, f);
//     fclose(f);

//     return (rd == len) ? 0 : -1;
// }

// #endif