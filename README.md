# Affine Cipher — Python Implementation

## What Is the Affine Cipher?

The Affine Cipher is a **monoalphabetic substitution cipher** that maps each letter of the
alphabet to a unique ciphertext letter using a linear mathematical function.  
It generalises both the **Caesar cipher** and the **Atbash cipher**.

---

## Mathematical Formulas

| Operation  | Formula |
|-----------|---------|
| **Encryption** | `f(x) = (A·x + B) mod 26` |
| **Decryption** | `x = A' · (y − B) mod 26` |

Where:
- `x` — numeric value of the plaintext letter (A=0, B=1, …, Z=25)
- `y` — numeric value of the ciphertext letter
- `A` — multiplicative key
- `B` — additive key (shift)
- `A'` — modular multiplicative inverse of `A` (mod 26)

---

## Key Constraints

### Constraint on A (Bezout's Theorem)
`A` must be **coprime with 26** — i.e. `gcd(A, 26) = 1`.  
If `A` is not coprime with 26, a single ciphertext letter will map to multiple
plaintext letters, making unique decryption impossible.

**Valid values of A:**
```
1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
```
(12 values total)

> **Note:** A = −1 is equivalent to A = 25 (since 25 ≡ −1 mod 26).

### Constraint on B
`B` can be **any integer**.  
All values of `B` modulo 26 are equivalent, so `B = −1` is the same as `B = 25`.

### Total Keyspace
```
12 (valid A values) × 26 (B values) = 312 possible keys
```

---

## Affine Cipher Variants

| Variant | A | B | Notes |
|---------|---|---|-------|
| **Caesar cipher** | 1 | shift | Identity multiplication; pure shift |
| **Multiplicative cipher** | any valid A | 0 | No additive shift |
| **Atbash cipher** | −1 (≡ 25) | −1 (≡ 25) | Reverses the alphabet |

---

## Example

**Key:** A = 5, B = 8  
**Plaintext:** `AFFINECIPHERR`

| Step | Label | A | F | F | I | N | E | C | I | P | H | E | R |
|------|-------|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Plaintext | A | F | F | I | N | E | C | I | P | H | E | R |
| 2 | x | 0 | 5 | 5 | 8 | 13 | 4 | 2 | 8 | 15 | 7 | 4 | 17 |
| 3 | 5x + 8 | 8 | 33 | 33 | 48 | 73 | 28 | 18 | 48 | 83 | 43 | 28 | 93 |
| 4 | mod 26 | 8 | 7 | 7 | 22 | 21 | 2 | 18 | 22 | 5 | 17 | 2 | 15 |
| 5 | Ciphertext | I | H | H | W | V | C | S | W | F | R | C | P |

**Ciphertext:** `IHHWVCSWFRCP`

### Decryption
The inverse of A=5 modulo 26 is **A' = 21** (since 5 × 21 = 105 ≡ 1 mod 26).

**Formula:** `x = 21 · (y − 8) mod 26`

---

## Attacks on the Affine Cipher

### 1. Brute Force
With only **312 valid key combinations**, an attacker can try every possible key
and inspect the output for readable text. This is the primary weakness.

### 2. Frequency Analysis
Because it is a monoalphabetic cipher, letter frequency patterns are preserved.
The most frequent letters in English (E, T, A) will correspond to the most frequent
letters in the ciphertext, allowing an attacker to solve for A and B algebraically
using a system of two equations.

---

## File Structure

```
affine_cipher.py
│
├── letter_to_num(ch)               — 'A' → 0, 'Z' → 25
├── num_to_letter(n)                — 0 → 'A', 25 → 'Z'
├── mod_inverse(a, m=26)            — Extended Euclidean algorithm
│
├── encrypt(plaintext, A, B)        — Affine encryption
├── decrypt(ciphertext, A, B)       — Affine decryption
│
├── substitution_table(A, B)        — Returns full 26-letter mapping dict
├── print_substitution_table(A, B)  — Prints the table
│
├── show_encryption_steps(...)      — Step-by-step table
├── show_decryption_steps(...)      — Step-by-step table
│
└── brute_force_attack(ciphertext)  — Returns all 312 decryption candidates
```

---


## Running the Demo

```bash
python affine_cipher.py
```

- Step-by-step encryption and decryption tables for `AFFINECIPHERR` with A=5, B=8
- The full substitution table for that key
- A brute-force attack showing all 312 candidates with the correct key highlighted

---