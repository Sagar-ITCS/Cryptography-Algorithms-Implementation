from Crypto.Hash import SHA256, SHA512


def compute_hash(data: bytes, alg: str = "sha256") -> str:
    alg = alg.lower()
    if alg == "sha256":
        h = SHA256.new(data=data)
    elif alg == "sha512":
        h = SHA512.new(data=data)
    else:
        raise ValueError("Unsupported algorithm")
    return h.hexdigest()
