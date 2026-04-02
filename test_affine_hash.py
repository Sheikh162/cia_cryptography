"""
Test Script — encrypt -> hash -> decrypt round-trip

Each test encrypts a plaintext, hashes the ciphertext, then decrypts
and checks that the original message is recovered correctly.
"""

from affine_cipher import encrypt, decrypt, VALID_A_VALUES
from hashing import poly_hash


def run_round_trip(plaintext, A, B, label=""):
    """Encrypt, hash, then decrypt. Return all results in a dict."""
    ciphertext = encrypt(plaintext, A, B)
    digest     = poly_hash(ciphertext)
    recovered  = decrypt(ciphertext, A, B)
    passed     = recovered.replace(" ", "") == plaintext.upper().replace(" ", "")
    return {
        "label"      : label,
        "plaintext"  : plaintext.upper(),
        "A"          : A,
        "B"          : B,
        "ciphertext" : ciphertext,
        "digest"     : digest,
        "recovered"  : recovered,
        "passed"     : passed,
    }


def print_result(r):
    print(f"\n  Label      : {r['label']}")
    print(f"  Plaintext  : {r['plaintext']}")
    print(f"  Key        : A={r['A']}, B={r['B']}")
    print(f"  Ciphertext : {r['ciphertext']}")
    print(f"  Hash       : {r['digest'][:32]}")
    print(f"               {r['digest'][32:]}")
    print(f"  Recovered  : {r['recovered']}")
    status = "PASS" if r['passed'] else "FAIL"
    print(f"  Result     : {status}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_worked_example_1():
    """Worked Example 1 — A=5, B=8 (matches lecture slide values)"""
    print("\n--- Worked Example 1 (A=5, B=8) ---")
    r = run_round_trip("AFFINECIPHERR", A=5, B=8, label="Example 1")
    print_result(r)

    expected = "IHHWVCSWFRCPP"
    ct_ok = r['ciphertext'] == expected
    print(f"  Ciphertext check : {'PASS' if ct_ok else 'FAIL'} (expected {expected})")
    return r['passed'] and ct_ok


def test_worked_example_2():
    """Worked Example 2 — A=7, B=13"""
    print("\n--- Worked Example 2 (A=7, B=13) ---")
    r = run_round_trip("CRYPTOGRAPHY", A=7, B=13, label="Example 2")
    print_result(r)
    return r['passed']


def test_all_valid_A_values():
    """Round-trip must work for every valid A and a sample of B values."""
    print("\n--- All Valid A Values ---")
    all_passed = True
    for A in VALID_A_VALUES:
        for B in [0, 8, 13, 25]:
            r = run_round_trip("TESTMESSAGE", A, B)
            if not r['passed']:
                print(f"  FAIL: A={A}, B={B} -> '{r['recovered']}'")
                all_passed = False
    status = "PASS" if all_passed else "FAIL"
    print(f"  Result: {status} ({len(VALID_A_VALUES) * 4} combinations tested)")
    return all_passed


def test_non_alpha_preserved():
    """Spaces and punctuation should pass through unchanged."""
    print("\n--- Non-Alphabetic Characters ---")
    r = run_round_trip("HELLO, WORLD! 123", A=5, B=8, label="With punctuation")
    print_result(r)
    ct = r['ciphertext']
    preserved = ct[5] == ',' and ct[6] == ' ' and ct[12] == '!'
    print(f"  Punctuation preserved: {'PASS' if preserved else 'FAIL'}")
    return r['passed'] and preserved


def test_invalid_A_raises_error():
    """A values that share a factor with 26 must raise an error."""
    print("\n--- Invalid A Values ---")
    invalid = [2, 4, 6, 8, 10, 12, 13, 14]
    all_raised = True
    for A in invalid:
        try:
            encrypt("TEST", A, 0)
            print(f"  FAIL: A={A} should have raised an error")
            all_raised = False
        except ValueError:
            print(f"  PASS: A={A} correctly rejected")
    return all_raised


def test_hash_same_input_same_output():
    """The same input must always produce the same hash."""
    print("\n--- Hash Determinism ---")
    d1, d2, d3 = poly_hash("HELLO"), poly_hash("HELLO"), poly_hash("HELLO")
    passed = d1 == d2 == d3
    print(f"  All three digests match: {'PASS' if passed else 'FAIL'}")
    print(f"  Digest: {d1}")
    return passed


def test_hash_avalanche():
    """One character change should flip most of the output bits."""
    print("\n--- Hash Avalanche Effect ---")
    d1 = poly_hash("SECRET")
    d2 = poly_hash("SECRES")
    diff = sum(c1 != c2 for c1, c2 in zip(d1, d2))
    pct  = diff / len(d1) * 100
    print(f"  'SECRET' -> {d1}")
    print(f"  'SECRES' -> {d2}")
    print(f"  Characters changed: {diff}/64 ({pct:.1f}%)")
    passed = pct > 30
    print(f"  Result: {'PASS' if passed else 'FAIL'}")
    return passed


def test_hash_edge_cases():
    """Hash should work on empty strings and very long inputs."""
    print("\n--- Hash Edge Cases ---")
    try:
        poly_hash("")
        poly_hash("A" * 10_000)
        print("  PASS: empty and 10,000-char inputs both handled")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  Test Cases — Affine Cipher + Polynomial Rolling Hash")
    print("=" * 60)

    tests = [
        ("Worked Example 1",        test_worked_example_1),
        ("Worked Example 2",        test_worked_example_2),
        ("All Valid A Values",      test_all_valid_A_values),
        ("Non-Alpha Preserved",     test_non_alpha_preserved),
        ("Invalid A Raises Error",  test_invalid_A_raises_error),
        ("Hash Determinism",        test_hash_same_input_same_output),
        ("Hash Avalanche Effect",   test_hash_avalanche),
        ("Hash Edge Cases",         test_hash_edge_cases),
    ]

    results = {name: fn() for name, fn in tests}

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(results.values())
    print(f"\n  {passed}/{len(results)} tests passed")
    print("=" * 60)