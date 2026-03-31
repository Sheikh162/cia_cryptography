import math
import string

ALPHABET_SIZE = 26
VALID_A_VALUES = [a for a in range(1, ALPHABET_SIZE) if math.gcd(a, ALPHABET_SIZE) == 1]
# [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def letter_to_num(ch: str) -> int:
    """Convert an uppercase letter to its index (A=0, Z=25)."""
    return ord(ch.upper()) - ord('A')


def num_to_letter(n: int) -> str:
    """Convert an index (0-25) back to an uppercase letter."""
    return chr(n % ALPHABET_SIZE + ord('A'))


def mod_inverse(a: int, m: int = ALPHABET_SIZE) -> int:
    """
    Returns modular multiplicative inverse of a (mod m) using extended Euclidean algorithm.

    Raises ValueError if gcd(a, m) != 1 (i.e. inverse doesn't exist).
    """
    if math.gcd(a, m) != 1:
        raise ValueError(
            f"A={a} and alphabet size {m} are NOT coprime — "
            "the modular inverse does not exist and decryption is impossible.\n"
            f"Valid A values: {VALID_A_VALUES}"
        )
    # Extended Euclidean algorithm
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % m


def encrypt(plaintext: str, A: int, B: int) -> str:
    if math.gcd(A, ALPHABET_SIZE) != 1:
        raise ValueError(
            f"A={A} is not coprime with {ALPHABET_SIZE}. "
            f"Choose from: {VALID_A_VALUES}"
        )
    B = B % ALPHABET_SIZE  # normalise negative B values

    ciphertext = []
    for ch in plaintext:
        if ch.isalpha():
            x = letter_to_num(ch)
            y = (A * x + B) % ALPHABET_SIZE
            ciphertext.append(num_to_letter(y))
        else:
            ciphertext.append(ch)          # preserve spaces, punctuation, etc.
    return ''.join(ciphertext)


def decrypt(ciphertext: str, A: int, B: int) -> str:
    A_inv = mod_inverse(A)          # raises ValueError if not coprime
    B = B % ALPHABET_SIZE

    plaintext = []
    for ch in ciphertext:
        if ch.isalpha():
            y = letter_to_num(ch)
            x = (A_inv * (y - B)) % ALPHABET_SIZE
            plaintext.append(num_to_letter(x))
        else:
            plaintext.append(ch)
    return ''.join(plaintext)


def brute_force_attack(ciphertext: str) -> list[dict]:
    """
    Try all valid (A, B) key combinations and return every decryption.

    With 12 valid A values and 26 B values there are 12 * 26 = 312 candidates.

    Returns
    -------
    list of dict, each with keys: 'A', 'B', 'plaintext'
    """
    results = []
    for A in VALID_A_VALUES:
        for B in range(ALPHABET_SIZE):
            try:
                pt = decrypt(ciphertext, A, B)
                results.append({'A': A, 'B': B, 'plaintext': pt})
            except ValueError:
                pass   # shouldn't happen since we iterate over valid A values
    return results


def substitution_table(A: int, B: int) -> dict[str, str]:
    """
    Return the full substitution table for key (A, B) as a dict
    mapping each plaintext letter → ciphertext letter.
    """
    if math.gcd(A, ALPHABET_SIZE) != 1:
        raise ValueError(f"A={A} is not coprime with 26.")
    table = {}
    for i, letter in enumerate(string.ascii_uppercase):
        cipher_index = (A * i + B) % ALPHABET_SIZE
        table[letter] = num_to_letter(cipher_index)
    return table


def print_substitution_table(A: int, B: int) -> None:
    """Print the substitution table for key (A, B)."""
    table = substitution_table(A, B)
    print(f"\nSubstitution table for A={A}, B={B}  [f(x) = ({A}x + {B}) mod 26]")
    print("Plain  : " + " ".join(table.keys()))
    print("Cipher : " + " ".join(table.values()))


def show_encryption_steps(plaintext: str, A: int, B: int) -> None:
    """
    Print a step-by-step encryption table.
    Only alphabetic characters are processed.
    """
    letters = [ch for ch in plaintext.upper() if ch.isalpha()]
    x_vals  = [letter_to_num(ch) for ch in letters]
    step3   = [A * x + B for x in x_vals]
    step4   = [v % ALPHABET_SIZE for v in step3]
    cipher  = [num_to_letter(v) for v in step4]

    col_w = max(len(str(max(step3, default=0))), 4) + 1

    print(f"\nEncryption  |  f(x) = ({A}x + {B}) mod 26")
    print("-" * (col_w * len(letters) + 16))
    print(f"{'STEP 1 plaintext':<20}" + "".join(f"{c:>{col_w}}" for c in letters))
    print(f"{'STEP 2 x':<20}"         + "".join(f"{v:>{col_w}}" for v in x_vals))
    print(f"{'STEP 3 ({A}x+{B})':<20}"      + "".join(f"{v:>{col_w}}" for v in step3))
    print(f"{'STEP 4 mod 26':<20}"    + "".join(f"{v:>{col_w}}" for v in step4))
    print(f"{'STEP 5 ciphertext':<20}" + "".join(f"{c:>{col_w}}" for c in cipher))
    print()


def show_decryption_steps(ciphertext: str, A: int, B: int) -> None:
    """
    Print a step-by-step decryption table.
    Only alphabetic characters are processed.
    """
    A_inv = mod_inverse(A)
    letters = [ch for ch in ciphertext.upper() if ch.isalpha()]
    y_vals  = [letter_to_num(ch) for ch in letters]
    step3   = [A_inv * (y - B) for y in y_vals]
    step4   = [v % ALPHABET_SIZE for v in step3]
    plain   = [num_to_letter(v) for v in step4]

    col_w = max(len(str(max(abs(v) for v in step3) if step3 else 0)), 4) + 1

    print(f"\nDecryption  |  x = {A_inv}(y - {B}) mod 26   [A'={A_inv}]")
    print("-" * (col_w * len(letters) + 20))
    print(f"{'STEP 1 ciphertext':<22}" + "".join(f"{c:>{col_w}}" for c in letters))
    print(f"{'STEP 2 y':<22}"          + "".join(f"{v:>{col_w}}" for v in y_vals))
    print(f"{'STEP 3 A*(y-B)':<22}"    + "".join(f"{v:>{col_w}}" for v in step3))
    print(f"{'STEP 4 mod 26':<22}"     + "".join(f"{v:>{col_w}}" for v in step4))
    print(f"{'STEP 5 plaintext':<22}"  + "".join(f"{c:>{col_w}}" for c in plain))
    print()


if __name__ == "__main__":
    A, B = 5, 8
    plaintext  = "AFFINECIPHERR"

    print(f"\n[1] Key: A={A}, B={B}")
    print(f"    Plaintext : {plaintext}")

    ciphertext = encrypt(plaintext, A, B)
    print(f"    Ciphertext: {ciphertext}")

    recovered  = decrypt(ciphertext, A, B)
    print(f"    Recovered : {recovered}")

    show_encryption_steps(plaintext, A, B)
    show_decryption_steps(ciphertext, A, B)
    print_substitution_table(A, B)

    # -----------------------------------------------------------------------
    # Coprime check demo
    # -----------------------------------------------------------------------
    
    print("\n" + "=" * 60)
    print("  VALID A VALUES (coprime with 26)")
    print("=" * 60)
    print(f"\n  {VALID_A_VALUES}")
    print(f"  Total combinations: {len(VALID_A_VALUES)} × 26 = {len(VALID_A_VALUES) * 26}")
    print()

    # -----------------------------------------------------------------------
    # Brute-force attack
    # -----------------------------------------------------------------------

    print("\n" + "=" * 60)
    print("  BRUTE-FORCE ATTACK  (312 key combinations)")
    print("=" * 60)
    secret = encrypt("SECRET", 7, 3)
    print(f"\nCiphertext to attack: '{secret}'  (key: A=7, B=3)")
    print("\nTop 5 results (showing A=7 row first):\n")
    results = brute_force_attack(secret)
    target  = next(r for r in results if r['A'] == 7 and r['B'] == 3)
    others  = [r for r in results if not (r['A'] == 7 and r['B'] == 3)][:4]
    for r in [target] + others:
        marker = "  ← CORRECT KEY" if r['A'] == 7 and r['B'] == 3 else ""
        print(f"  A={r['A']:>2}, B={r['B']:>2}  →  {r['plaintext']}{marker}")

