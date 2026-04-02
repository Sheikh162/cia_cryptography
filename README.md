# Affine Cipher + Polynomial Rolling Hash

---

## Files

```
affine_cipher.py    — Affine cipher encryption and decryption
hashing.py          — Custom polynomial rolling hash
test_affine_hash.py — Tests: encrypt -> hash -> decrypt round-trip
README.md           — This file
```

---

## Part 1 — Affine Cipher

### How it works

Every letter is assigned a number: A=0, B=1, C=2 … Z=25.

To **encrypt**, apply this formula to each letter's number:

```
ciphertext = (A * x + B) mod 26
```

To **decrypt**, reverse it:

```
plaintext = A' * (y - B) mod 26
```

Where `A'` is the modular inverse of `A` — the number such that `(A * A') mod 26 = 1`. This is found using the Extended Euclidean Algorithm.

The **key** is the pair `(A, B)`.

### Constraint on A

`A` must share no common factors with 26. If it does, two different letters could encrypt to the same ciphertext letter, making decryption impossible.

Valid A values: `1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25` (12 values)

`B` can be any number (it is normalised mod 26 internally).

Total possible keys: 12 × 26 = **312 combinations**.

### Special cases

| Cipher | A | B |
|--------|---|---|
| Caesar cipher | 1 | the shift amount |
| Multiplicative cipher | any valid A | 0 |
| Atbash cipher | 25 | 25 |

### Attacks

**Brute force** — with only 312 keys, an attacker can try all of them in milliseconds.

**Frequency analysis** — because every letter always maps to the same ciphertext letter, common letters like E and T still stand out. An attacker can use their frequency to solve for A and B directly.

---

## Part 2 — Polynomial Rolling Hash

### How it works

The hash treats the input text like a polynomial. Each character is a coefficient, the base `P` is the variable, and the result is computed mod a large prime `M`:

```
H = (c0 * P^(n-1) + c1 * P^(n-2) + ... + cn-1 * P^0) mod M
```

After this, a **finalisation step** stirs all the bits together to ensure every character of the input affects every bit of the output.

The final digest is 64 hex characters (256 bits), produced from 4 independent rounds with different seeds.

### Why this hash function — 3 reasons

**1. The modulus M = 2⁶¹ − 1 is a Mersenne prime**

A Mersenne prime has the property that its multiplicative group covers the full output range before repeating. In plain terms: the hash values spread out evenly and don't bunch up in certain spots. This is the same reason Mersenne primes are used in serious random number generators like Mersenne Twister.

**2. The base P = 131 shares no factors with M**

The hash works by treating the input as a polynomial. For two different inputs to accidentally produce the same hash value (a collision), they would need to satisfy a polynomial equation modulo a huge prime — which is computationally very hard to engineer. A poorly chosen base (like P=2) makes such collisions easy to construct deliberately.

**3. The finalisation step (mix64) gives strong avalanche behaviour**

A basic polynomial hash has a known weakness: changing a character near the end of the input barely affects the earlier parts of the accumulation. The mix64 step fixes this using a sequence of XOR, bit-shift, and multiply operations. XOR (exclusive OR) works at the bit level — it compares two bits and outputs 1 only when they differ. This makes it ideal for mixing, because it spreads the influence of each bit into other positions without any information being lost (unlike addition, XOR is perfectly reversible). The shifts expose high bits to low positions, the multiplications scatter them further, and the XORs blend everything together. The result is that changing even one character flips around 95% of the output hex characters — verified in the test cases.

---

## Worked Examples

### Example 1 — A=5, B=8

**Encryption** `f(x) = (5x + 8) mod 26`

| | A | F | F | I | N | E | C | I | P | H | E | R | R |
|-|---|---|---|---|---|---|---|---|---|---|---|---|---|
| x | 0 | 5 | 5 | 8 | 13 | 4 | 2 | 8 | 15 | 7 | 4 | 17 | 17 |
| 5x+8 | 8 | 33 | 33 | 48 | 73 | 28 | 18 | 48 | 83 | 43 | 28 | 93 | 93 |
| mod 26 | 8 | 7 | 7 | 22 | 21 | 2 | 18 | 22 | 5 | 17 | 2 | 15 | 15 |
| Cipher | I | H | H | W | V | C | S | W | F | R | C | P | P |

**Plaintext:** `AFFINECIPHERR` → **Ciphertext:** `IHHWVCSWFRCPP`

**Hash of ciphertext:**
```
6ca5bb243ab78375eb6730353fa7afbc
b6514b521ac4e1376d8a2115fcc38ca6
```

**Decryption** uses A' = 21 (since 5 × 21 = 105 ≡ 1 mod 26): `x = 21 * (y - 8) mod 26` → recovers `AFFINECIPHERR` ✓

---

### Example 2 — A=7, B=13

**Encryption** `f(x) = (7x + 13) mod 26`

| | C | R | Y | P | T | O | G | R | A | P | H | Y |
|-|---|---|---|---|---|---|---|---|---|---|---|---|
| x | 2 | 17 | 24 | 15 | 19 | 14 | 6 | 17 | 0 | 15 | 7 | 24 |
| 7x+13 | 27 | 132 | 181 | 118 | 146 | 111 | 55 | 132 | 13 | 118 | 62 | 181 |
| mod 26 | 1 | 2 | 25 | 14 | 16 | 7 | 3 | 2 | 13 | 14 | 10 | 25 |
| Cipher | B | C | Z | O | Q | H | D | C | N | O | K | Z |

**Plaintext:** `CRYPTOGRAPHY` → **Ciphertext:** `BCZOQHDCNOKZ`

**Hash of ciphertext:**
```
435ae956b17fd442772ed970adcef568
2eba1203efcfbbd04d9150c208d2401d
```

**Decryption** uses A' = 15 (since 7 × 15 = 105 ≡ 1 mod 26): `x = 15 * (y - 13) mod 26` → recovers `CRYPTOGRAPHY` ✓

---

## How to Run

Requires Python 3.10+. No packages to install.

```bash
# Run the cipher demo
python affine_cipher.py

# Run the hash demo
python hashing.py

# Run all tests (encrypt -> hash -> decrypt)
python test_affine_hash.py
```