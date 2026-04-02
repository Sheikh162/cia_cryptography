# Polynomial Rolling Hash — see README.md for how it works and why this approach was chosen.

# --- Constants ---

P = 131              # base: a prime larger than any ASCII value
M = (1 << 61) - 1   # modulus: the Mersenne prime 2^61 - 1
ROUNDS = 4           # number of independent hash words (4 x 64 bits = 256-bit digest)

ROUND_SEEDS = [0x1A2B3C4D, 0x5E6F7A8B, 0x9C0D1E2F, 0xABCDEF01]


# --- Finalisation mix ---

def mix64(h):
    """Stir all bits together so every input bit affects every output bit."""
    h = h & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 30)
    h = (h * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 27)
    h = (h * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 31)
    return h


# --- Core polynomial accumulation ---

def poly_hash_word(data, seed):
    """Accumulate one hash word over the input bytes, then finalise."""
    h = seed % M
    for byte in data:
        h = (h * P + byte) % M
    # Mix in the length so "aaa" and "aaaa" never collide trivially
    h = mix64(h ^ (len(data) * P) % M)
    return h


# --- Public API ---

def poly_hash(text):
    """Hash any string and return a 64-character hex digest (256 bits)."""
    data = text.encode('utf-8')
    words = []
    for i in range(ROUNDS):
        seed = ROUND_SEEDS[i] ^ (M >> (i * 7))
        words.append(poly_hash_word(data, seed))
    return ''.join(f'{w:016x}' for w in words)


# --- Demo ---

if __name__ == "__main__":
    print("=== Polynomial Rolling Hash Demo ===\n")

    samples = ["AFFINECIPHERR", "Hello, World!", ""]
    for s in samples:
        print(f"Input  : {repr(s)}")
        print(f"Digest : {poly_hash(s)}\n")

    print("--- Avalanche Effect ---")
    d1 = poly_hash("SECRET")
    d2 = poly_hash("SECRES")
    diff = sum(c1 != c2 for c1, c2 in zip(d1, d2))
    print(f"'SECRET' -> {d1}")
    print(f"'SECRES' -> {d2}")
    print(f"Characters changed: {diff}/64 ({diff/64*100:.1f}%)")