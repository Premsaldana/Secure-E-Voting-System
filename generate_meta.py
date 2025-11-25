import json, base64, secrets, time, os

from shamir_lib import shamir_reconstruct_internal

DATA_DIR = "data"
META_PATH = os.path.join(DATA_DIR, "meta.json")

# Generate AES-256 key
aes_key = secrets.token_bytes(32)
secret_int = int.from_bytes(aes_key, "big")

# Generate a 257-bit prime
def is_prime(n):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0 and n != p:
            return False
    # Miller–Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1
    for _ in range(8):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

print("Generating 257-bit prime...")

while True:
    p = secrets.randbits(257) | (1 << 256) | 1
    if is_prime(p):
        break

print("Prime generated.")

# Shamir split (n=5, k=3)
def shamir_split(secret_int, n=5, k=3, p=None):
    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for exp, coef in enumerate(coeffs):
            y = (y + coef * pow(x, exp, p)) % p
        shares.append([x, y])
    return shares

shares = shamir_split(secret_int, 5, 3, p)

# Verify
test_recon = shamir_reconstruct_internal([tuple(s) for s in shares[:3]], p)
print("Reconstruction OK:", test_recon == secret_int)

meta = {
    "aes_key": base64.b64encode(aes_key).decode(),
    "prime": p,
    "shamir_shares": shares,
    "used_ids": []
}

os.makedirs(DATA_DIR, exist_ok=True)
with open(META_PATH, "w") as f:
    json.dump(meta, f, indent=2)

print("\nNEW META.JSON GENERATED!")
print("Use these 3 valid shares at the tally:")
for s in shares[:3]:
    print(f"{s[0]}:{s[1]}")
