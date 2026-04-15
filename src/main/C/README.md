# A C Executable Specification of ML-KEM-1024 with ACVP Validation

## Overview
This repository provides a low-level executable specification of the ML-KEM-1024 key encapsulation mechanism based on **NIST FIPS 203**.

The implementation is written in **C** to clearly handle polynomial arithmetic (e.g., NTT, modular operations).

In addition to the core algorithm, this repository includes a testing pipeline that verifies:
- internal functional correctness (mathematical + algorithm level)
- compliance with **NIST ACVP Known Answer Tests (KATs)**

---

## Usage

### 1. Run Internal Tests

Validates mathematical components and executes a full KEM flow:



---

### 2. Run ACVP (KAT) Validation

Validates implementation against official NIST test vectors:

```bash
gcc !(test).c -o test_ml_kem_KAT
./test_ml_kem_KAT
```

---  
