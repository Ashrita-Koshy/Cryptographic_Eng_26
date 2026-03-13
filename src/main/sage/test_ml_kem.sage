# load ml_kem.sage
load("ml_kem.sage")

import os
import random

# test ML-KEM functions that are important
def test_ml_kem_functions():
    print("Testing ML-KEM functions...")

    try:
        # Error bound test
        x = random.randint(0, q - 1)
        comp = Compress(du, x)
        decomp = Decompress(du, comp)

        error_bound = round(q / (2**(du + 1)))
        diff = min((x - decomp) % q, (decomp - x) % q)

        assert diff <= error_bound, "ML-KEM functions failed: Error bound exceeded"
        print("ML-KEM functions test passed: Error bound satisfied")

        # NTT and NTTInverse test
        f = [random.randint(0, q - 1) for _ in range(n)]
        f_hat = NTT(f)
        f_recovered = NTTInverse(f_hat)

        assert f == f_recovered, "ML-KEM functions failed: NTT and NTTInverse do not match"
        print("ML-KEM functions test passed: NTT and NTTInverse match")

        # Conversion test (BytesToBits and BitsToBytes)
        original_bytes = [random.randint(0, 255) for _ in range(32)]
        bits = BytesToBits(original_bytes)
        recovered_bytes = BitsToBytes(bits)

        assert original_bytes == recovered_bytes, "ML-KEM functions failed: BytesToBits and BitsToBytes do not match"
        print("ML-KEM functions test passed: BytesToBits and BitsToBytes match")

    except Exception as e:
        print(f"ML-KEM functions test failed: {e}")
        import traceback
        traceback.print_exc()
        
# test full cycle of ML-KEM
def test_ml_kem():
    print("Testing ML-KEM...")

    try:
        d = os.urandom(32) # random 32-byte seed for generating the key pair
        z = os.urandom(32) # for implicit rejection
        m = os.urandom(32) # 32-byte message to encapsulate

        # Key Generation
        (ek, dk) = ML_KEM_KeyGen_internal(d, z)

        # Encapsulation
        (K_enc, c) = ML_KEM_Encaps_internal(ek, m)

        # Decapsulation
        (K_dec) = ML_KEM_Decaps_internal(dk, c)

        assert K_enc == K_dec, "ML-KEM failed: Decapsulated key does not match encapsulated key"
        print("ML-KEM test passed: Decapsulated key matches encapsulated key")

    except Exception as e:
        print(f"ML-KEM test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ml_kem_functions()
    test_ml_kem()


