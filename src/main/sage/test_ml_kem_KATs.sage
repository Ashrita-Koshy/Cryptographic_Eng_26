# test_ml_kem_KATs.sage
load("ml_kem.sage")

import os
import json

def load_json_safe(filepath):

    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        return None

def test_acvp_keygen(prompt_file, expected_file):

    print(f"\n==================================================")
    print(f"ML-KEM-keyGen-FIPS203 Starting validation: {prompt_file}")
    
    prompt_data = load_json_safe(prompt_file)
    expected_data = load_json_safe(expected_file)
    if not prompt_data or not expected_data: return

    # map expected results by tcId (Test Case ID)
    expected_results = {}
    for tg in expected_data.get('testGroups', []):
        for t in tg.get('tests', []):
            expected_results[t['tcId']] = {
                'ek': t.get('ek', '').upper(),
                'dk': t.get('dk', '').upper()
            }

    passed, skipped = 0, 0

    for tg in prompt_data.get('testGroups', []):
        # skip 512 and 768 test cases since our implementation only supports 1024.
        if tg.get('parameterSet') != "ML-KEM-1024":
            skipped += len(tg.get('tests', []))
            continue
            
        for t in tg.get('tests', []):
            tcId = t['tcId']
            
            # ACVP KeyGen mode provides seeds z and d.
            z_seed = bytes.fromhex(t['z'])
            d_seed = bytes.fromhex(t['d'])
            # execute our KeyGen function
            my_pk, my_sk = ML_KEM_KeyGen_internal(d_seed, z_seed)
            
            # convert output back to uppercase hex strings for comparison
            my_pk_hex = bytes(my_pk).hex().upper()
            my_sk_hex = bytes(my_sk).hex().upper()
            
            # extract expected answer
            exp = expected_results.get(tcId)
            if not exp: continue
            
            try:
                # strict equality assertions
                assert my_pk_hex == exp['ek'], f"tcId {tcId}: Public key mismatch"
                assert my_sk_hex == exp['dk'], f"tcId {tcId}: Secret key mismatch"
                passed += 1
            except AssertionError as e:
                print(f"[-] KeyGen failed: {e}")
                return

    print(f"[SUCCESS] KeyGen tests completed! (Passed: {passed} / Skipped: {skipped})")


def test_acvp_encap_decap(prompt_file, expected_file):
    print(f"\n==================================================")
    print(f"ML-KEM-encapDecap-FIPS203 Starting validation: {prompt_file}")
    
    prompt_data = load_json_safe(prompt_file)
    expected_data = load_json_safe(expected_file)
    if not prompt_data or not expected_data: return

    # map expected results by tcId
    expected_results = {}
    for tg in expected_data.get('testGroups', []):
        for t in tg.get('tests', []):
            expected_results[t['tcId']] = t

    passed, skipped = 0, 0

    # skip if it's not 1024.
    for tg in prompt_data.get('testGroups', []):
        if tg.get('parameterSet') != "ML-KEM-1024":
            skipped += len(tg.get('tests', []))
            continue
            
        func_type = tg.get('function') # 'encapsulation' or 'decapsulation'
        
        for t in tg.get('tests', []):
            tcId = t['tcId']
            exp = expected_results.get(tcId)
            if not exp: continue

            try:
                if func_type == "encapsulation":
                    # Encapsulation validation
                    ek = bytes.fromhex(t['ek'])
                    
                    # In ACVP specs, message entropy is denoted as 'msg', 'm', or 'payload'
                    msg_hex = t.get('msg', t.get('m', t.get('payload', '')))
                    m_seed = bytes.fromhex(msg_hex)
                    
                    my_k, my_c = ML_KEM_Encaps_internal(ek, m_seed)
                    
                    my_k_hex = bytes(my_k).hex().upper()
                    my_c_hex = bytes(my_c).hex().upper()
                    
                    assert my_c_hex == exp.get('c', '').upper(), f"tcId {tcId}: Ciphertext (c) mismatch"
                    assert my_k_hex == exp.get('k', '').upper(), f"tcId {tcId}: Shared key (k) mismatch"
                    passed += 1

                elif func_type == "decapsulation":
                    # Decapsulation validation
                    dk = bytes.fromhex(t['dk'])
                    c = bytes.fromhex(t['c'])
                    expected_k_prompt = t.get('k', '').upper() # Target K from prompt
                    
                    my_k = ML_KEM_Decaps_internal(dk, c)
                    my_k_hex = bytes(my_k).hex().upper()
                    
                    # True or False depending on whether our computed K matches the expected K from the prompt
                    my_test_passed = (my_k_hex == expected_k_prompt)
                    
                    # The expectedResult contains whether this match should pass or fail 
                    # tests the implicit rejection mechanism
                    expected_pass = exp.get('testPassed')
                    
                    if expected_pass is not None:
                        assert my_test_passed == expected_pass, f"tcId {tcId}: Implicit Rejection logic failed"
                    else:
                        assert my_k_hex == exp.get('k', '').upper(), f"tcId {tcId}: Recovered shared key (k) mismatch"
                        
                    passed += 1

            except AssertionError as e:
                print(f"[-] {func_type} failed: {e}")
                return

    print(f"[SUCCESS] EncapDecap tests completed! (Passed: {passed} / Skipped: {skipped})")


if __name__ == "__main__":

    KEYGEN_DIR = "known_answers_tests/ML-KEM-keyGen-FIPS203"
    ENCAP_DIR = "known_answers_tests/ML-KEM-encapDecap-FIPS203"
    
    #KeyGen validation
    test_acvp_keygen(
        prompt_file=f"{KEYGEN_DIR}/prompt.json", 
        expected_file=f"{KEYGEN_DIR}/expectedResults.json"
    )
    
    #EncapDecap validation
    test_acvp_encap_decap(
        prompt_file=f"{ENCAP_DIR}/prompt.json", 
        expected_file=f"{ENCAP_DIR}/expectedResults.json"
    )