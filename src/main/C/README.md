# A C Executable Specification of ML-KEM-1024 with ACVP Validation

## Overview
This repository provides a C executable specification of the ML-KEM-1024 key encapsulation mechanism based on NIST FIPS 203.

The implementation is written in C to support low-level execution of the ML-KEM-1024 procedures, including polynomial arithmetic, Kyber-PKE components, top-level key generation / encapsulation / decapsulation, and runtime randomness generation.

In addition to the core algorithm, this repository includes a testing pipeline that verifies:
- internal functional correctness
- compliance with NIST ACVP Known Answer Tests (KATs)
- board-side execution on the target platform

---

## Repository Structure

```
.
├── known_answers_tests/
    ├── ML-KEM-keyGen-FIPS203/
    └── ML-KEM-encapDecap-FIPS203/
├── README.md
├── aes.c
├── aes.h
├── auxiliary.c
├── auxiliary.h
├── cJSON.c
├── cJSON.h
├── config.h
├── fips202.c
├── fips202.h
├── kem.c
├── kem.h
├── main.c
├── ntt.c
├── ntt.h
├── pke.c
├── pke.h
├── rng.c
├── rng.h
├── test_ml_kem_KAT.c
└── test_ml_kem_KAT.h
```

### Core Files

- **`kem.c`** / **`kem.h`**  
  Core implementation of ML-KEM-1024
  - key generation
  - encapsulation
  - decapsulation

- **`pke.c`** / **`pke.h`**  
  Underlying Kyber-PKE implementation
  - public-key generation
  - encryption
  - decryption

- **`ntt.c`** / **`ntt.h`**  
  Number Theoretic Transform implementation
  - forward NTT
  - inverse NTT
  - NTT multiplication

- **`auxiliary.c`** / **`auxiliary.h`**  
  Supporting arithmetic and encoding routines
  - compression / decompression
  - byte encoding / decoding
  - sampling support

- **`fips202.c`** / **`fips202.h`**  
  SHA-3 / SHAKE implementation used by ML-KEM

- **`rng.c`** / **`rng.h`**  
  RNG support for top-level API execution
  - AES-256 based CTR-DRBG
  - ADC-based seed collection
  - randombytes() interface

- **`main.c`**  
  Board-side execution test
  - runs key generation, encapsulation, and decapsulation
  - checks whether both sides derive the same shared secret

- **`test_ml_kem_KAT.c`** / **`test_ml_kem_KAT.h`**  
  ACVP validation program
  - parses official NIST test vectors
  - validates key generation / encapsulation / decapsulation
  - verifies implicit rejection behavior

- **`known_answers_tests/`**  
  JSON-formatted ACVP test vectors from NIST
  - ML-KEM-keyGen-FIPS203/ -> key generation validation
  - ML-KEM-encapDecap-FIPS203/ -> encapsulation/decapsulation validation

- **`aes.c`** / **`aes.h`**  
  AES implementation used by the RNG code

- **`config.h`**  
  Global constants and parameter definitions for ML-KEM-1024
  
---

## Prerequisites

- C compiler
- Texas Instruments Code Composer Studio (CCS)
- TI compiler / CCS project setup
- TivaWare / TM4C1294 device support
- TM4C1294 Connected LaunchPad

---

## Usage

### 1. Run ACVP (KAT) Validation

Validates the implementation against official NIST test vectors:

```bash
test_ml_kem_KAT.c
```

---

### 2. Run Board-Side Execution

Runs the top-level ML-KEM-1024 flow on the target board:

```bash
main.c
```

---
