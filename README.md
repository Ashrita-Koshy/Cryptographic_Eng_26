# ML-KEM-1024 Executable Specifications

## Overview
This repository contains two executable specifications of ML-KEM-1024 based on NIST FIPS 203:
- a SageMath implementation for high-level validation
- a C implementation for low-level execution, ACVP validation, and board-side testing

The code is organized under `src/main/` with separate folders for each implementation.

---

## Repository Structure

```
.
├── src/main/
│   ├── C/
│   │   ├── known_answers_tests/
│   │       ├── ML-KEM-keyGen-FIPS203/
│   │       └── ML-KEM-encapDecap-FIPS203/
│   │   ├── README.md
│   │   ├── aes.c
│   │   ├── auxiliary.c
│   │   ├── cJSON.c
│   │   ├── config.h
│   │   ├── fips202.c
│   │   ├── kem.c
│   │   ├── main.c
│   │   ├── ntt.c
│   │   ├── pke.c
│   │   ├── rng.c
│   │   └── test_ml_kem_KAT.c
│   └── sage/
│       ├── known_answers_tests/
│           ├── ML-KEM-keyGen-FIPS203/
│           └── ML-KEM-encapDecap-FIPS203/
│       ├── README.md
│       ├── ml_kem.sage
│       ├── test_ml_kem.sage
│       └── test_ml_kem_KATs.sage
├── .gitignore
└── README.md
```

---

## Implementations

### C
The C implementation supports:
- ML-KEM-1024 key generation, encapsulation, and decapsulation
- ACVP Known Answer Test validation
- board-side execution on the TM4C1294 Connected LaunchPad

See:

    src/main/C/README.md

### SageMath
The SageMath implementation supports:
- high-level executable specification of ML-KEM-1024
- internal validation of algorithm behavior
- ACVP Known Answer Test validation

See:

    src/main/sage/README.md
