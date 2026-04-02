"""
Affine Cipher — Encryption and Decryption

How it works:
  Each letter is converted to a number (A=0, B=1, ... Z=25).
  Encryption applies: (A * number + B) mod 26, then converts back to a letter.
  Decryption reverses this using the modular inverse of A.

The key is the pair (A, B).
A must share no common factors with 26, otherwise decryption becomes impossible.
"""

import math
import string

ALPHABET_SIZE = 26
VALID_A_VALUES = [a for a in range(1, ALPHABET_SIZE) if math.gcd(a, ALPHABET_SIZE) == 1]


def letter_to_num(ch):
    return ord(ch.upper()) - ord('A')


def num_to_letter(n):
    return chr(n % ALPHABET_SIZE + ord('A'))


def mod_inverse(a, m=ALPHABET_SIZE):
    """
    Find A' such that (A * A') mod 26 = 1.
    Needed to reverse the encryption formula during decryption.
    Uses the Extended Euclidean Algorithm.
    """
    if math.gcd(a, m) != 1:
        raise ValueError(
            f"A={a} cannot be used — it shares a factor with 26.\n"
            f"Valid choices: {VALID_A_VALUES}"
        )
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


def encrypt(plaintext, A, B):
    """
    Encrypt using the Affine cipher with key (A, B).
    Spaces and punctuation are left unchanged.
    """
    if math.gcd(A, ALPHABET_SIZE) != 1:
        raise ValueError(f"A={A} is not valid. Choose from: {VALID_A_VALUES}")
    B = B % ALPHABET_SIZE
    result = []
    for ch in plaintext:
        if ch.isalpha():
            x = letter_to_num(ch)
            y = (A * x + B) % ALPHABET_SIZE
            result.append(num_to_letter(y))
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext, A, B):
    """Decrypt an Affine cipher message with key (A, B)."""
    A_inv = mod_inverse(A)
    B = B % ALPHABET_SIZE
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            y = letter_to_num(ch)
            x = (A_inv * (y - B)) % ALPHABET_SIZE
            result.append(num_to_letter(x))
        else:
            result.append(ch)
    return ''.join(result)


def brute_force_attack(ciphertext):
    """Try all 312 valid (A, B) combinations and return every possible decryption."""
    results = []
    for A in VALID_A_VALUES:
        for B in range(ALPHABET_SIZE):
            results.append({'A': A, 'B': B, 'plaintext': decrypt(ciphertext, A, B)})
    return results


def substitution_table(A, B):
    """Return which plaintext letter maps to which ciphertext letter."""
    if math.gcd(A, ALPHABET_SIZE) != 1:
        raise ValueError(f"A={A} is not valid.")
    return {
        letter: num_to_letter((A * i + B) % ALPHABET_SIZE)
        for i, letter in enumerate(string.ascii_uppercase)
    }


def show_encryption_steps(plaintext, A, B):
    """Print the step-by-step encryption table."""
    letters = [ch for ch in plaintext.upper() if ch.isalpha()]
    x_vals  = [letter_to_num(ch) for ch in letters]
    step3   = [A * x + B for x in x_vals]
    step4   = [v % ALPHABET_SIZE for v in step3]
    cipher  = [num_to_letter(v) for v in step4]
    w = max(len(str(max(step3, default=0))), 4) + 1

    print(f"\nEncryption  —  f(x) = ({A}x + {B}) mod 26")
    print(f"{'Plaintext':<22}" + "".join(f"{c:>{w}}" for c in letters))
    print(f"{'x':<22}" + "".join(f"{v:>{w}}" for v in x_vals))
    print(f"{'({A}x+{B})':<22}" + "".join(f"{v:>{w}}" for v in step3))
    print(f"{'mod 26':<22}" + "".join(f"{v:>{w}}" for v in step4))
    print(f"{'Ciphertext':<22}" + "".join(f"{c:>{w}}" for c in cipher))


def show_decryption_steps(ciphertext, A, B):
    """Print the step-by-step decryption table."""
    A_inv   = mod_inverse(A)
    letters = [ch for ch in ciphertext.upper() if ch.isalpha()]
    y_vals  = [letter_to_num(ch) for ch in letters]
    step3   = [A_inv * (y - B) for y in y_vals]
    step4   = [v % ALPHABET_SIZE for v in step3]
    plain   = [num_to_letter(v) for v in step4]
    w = max(len(str(max((abs(v) for v in step3), default=0))), 4) + 1

    print(f"\nDecryption  —  x = {A_inv} * (y - {B}) mod 26   (A' = {A_inv})")
    print(f"{'Ciphertext':<22}" + "".join(f"{c:>{w}}" for c in letters))
    print(f"{'y':<22}" + "".join(f"{v:>{w}}" for v in y_vals))
    print(f"{'A*(y-B)':<22}" + "".join(f"{v:>{w}}" for v in step3))
    print(f"{'mod 26':<22}" + "".join(f"{v:>{w}}" for v in step4))
    print(f"{'Plaintext':<22}" + "".join(f"{c:>{w}}" for c in plain))


if __name__ == "__main__":
    A, B = 5, 8
    plaintext = "AFFINECIPHERR"

    print("=== Affine Cipher Demo ===")
    print(f"\nKey       : A={A}, B={B}")
    print(f"Plaintext : {plaintext}")

    ciphertext = encrypt(plaintext, A, B)
    print(f"Encrypted : {ciphertext}")

    recovered = decrypt(ciphertext, A, B)
    print(f"Decrypted : {recovered}")

    show_encryption_steps(plaintext, A, B)
    show_decryption_steps(ciphertext, A, B)

    table = substitution_table(A, B)
    print(f"\nSubstitution table  [f(x) = ({A}x + {B}) mod 26]")
    print("Plain  : " + " ".join(table.keys()))
    print("Cipher : " + " ".join(table.values()))

    print("\n=== Valid A values (no common factor with 26) ===")
    print(VALID_A_VALUES)
    print(f"Total combinations: {len(VALID_A_VALUES)} x 26 = {len(VALID_A_VALUES) * 26}")

    print("\n=== Brute Force Attack Demo ===")
    secret = encrypt("SECRET", 7, 3)
    print(f"Ciphertext: '{secret}'  (key was A=7, B=3)")
    results = brute_force_attack(secret)
    target = next(r for r in results if r['A'] == 7 and r['B'] == 3)
    others = [r for r in results if not (r['A'] == 7 and r['B'] == 3)][:4]
    for r in [target] + others:
        marker = "  <- correct key" if r['A'] == 7 and r['B'] == 3 else ""
        print(f"  A={r['A']:>2}, B={r['B']:>2}  ->  {r['plaintext']}{marker}")