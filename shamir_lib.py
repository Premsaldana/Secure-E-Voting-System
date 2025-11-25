def shamir_reconstruct_internal(shares, p):
    x_s = [s[0] for s in shares]
    y_s = [s[1] for s in shares]
    k = len(shares)
    secret = 0

    for j in range(k):
        num = 1
        den = 1
        for i in range(k):
            if i != j:
                num = (num * (-x_s[i])) % p
                den = (den * (x_s[j] - x_s[i])) % p
        lagrange = num * pow(den, -1, p)
        secret = (secret + (y_s[j] * lagrange)) % p

    return secret