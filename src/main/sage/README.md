# A SageMath Executable Specification of ML-KEM-1024 with ACVP Validation

## Overview
This repository provides a high-level executable specification of the ML-KEM-1024 key encapsulation mechanism based on **NIST FIPS 203**.

The implementation is written in **SageMath** to clearly handle polynomial arithmetic (e.g., NTT, modular operations).

In addition to the core algorithm, this repository includes a testing pipeline that verifies:
- internal functional correctness (mathematical + algorithm level)
- compliance with **NIST ACVP Known Answer Tests (KATs)**

---

## Repository Structure

```
.
├── ml_kem.sage
├── test_ml_kem.sage
├── test_ml_kem_KATs.sage
├── README.md
└── known_answers_tests/
    ├── ML-KEM-keyGen-FIPS203/
    └── ML-KEM-encapDecap-FIPS203/
```

### Core Files

- **`ml_kem.sage`**  
  Core implementation of ML-KEM-1024  
  - polynomial arithmetic (NTT, compression)  
  - Kyber-PKE primitives  
  - key generation, encapsulation, decapsulation  

- **`test_ml_kem.sage`**  
  Internal validation script  
  - verifies correctness of individual components  
  - checks constraints (e.g., compression error bounds from FIPS 203)  
  - runs full KEM lifecycle (keygen → encap → decap)  

- **`test_ml_kem_KATs.sage`**  
  ACVP validation script  
  - parses official NIST test vectors  
  - validates keygen / encapsulation / decapsulation  
  - verifies implicit rejection behavior (CCA security requirement)  

- **`known_answers_tests/`**  
  JSON-formatted ACVP test vectors from NIST  
  - `ML-KEM-keyGen-FIPS203/` → key generation validation  
  - `ML-KEM-encapDecap-FIPS203/` → encapsulation/decapsulation validation  

---

## Prerequisites

- **SageMath**

---

## Usage

### 1. Run Internal Tests

Validates mathematical components and executes a full KEM flow:

```bash
sage test_ml_kem.sage
```

---

### 2. Run ACVP (KAT) Validation

Validates implementation against official NIST test vectors:

```bash
sage test_ml_kem_KATs.sage
```

---  
