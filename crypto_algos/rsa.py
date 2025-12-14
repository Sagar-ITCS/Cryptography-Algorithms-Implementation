"""
RSA helper: key generation, encrypt/decrypt (OAEP), sign/verify (PSS).
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


class RSAKeyPair:
    def __init__(self, priv_pem: bytes | None = None, pub_pem: bytes | None = None):
        self.priv_pem = priv_pem
        self.pub_pem = pub_pem

    @staticmethod
    def generate(bits: int = 2048) -> "RSAKeyPair":
        key = RSA.generate(bits)
        return RSAKeyPair(priv_pem=key.export_key("PEM"), pub_pem=key.publickey().export_key("PEM"))

    def export_private(self) -> bytes:
        return self.priv_pem

    def export_public(self) -> bytes:
        return self.pub_pem

    @staticmethod
    def from_private_pem(pem: bytes) -> "RSAKeyPair":
        key = RSA.import_key(pem)
        return RSAKeyPair(priv_pem=pem, pub_pem=key.publickey().export_key("PEM"))

    @staticmethod
    def from_public_pem(pem: bytes) -> "RSAKeyPair":
        return RSAKeyPair(priv_pem=None, pub_pem=pem)

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.pub_pem:
            raise ValueError("Public key required for encryption")
        key = RSA.import_key(self.pub_pem)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.priv_pem:
            raise ValueError("Private key required for decryption")
        key = RSA.import_key(self.priv_pem)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(ciphertext)

    # simple sign/verify helpers
    def sign(self, message: bytes) -> bytes:
        if not self.priv_pem:
            raise ValueError("Private key required for signing")
        key = RSA.import_key(self.priv_pem)
        h = SHA256.new(message)
        signer = pss.new(key)
        return signer.sign(h)

    def verify(self, message: bytes, signature: bytes) -> bool:
        if not self.pub_pem:
            raise ValueError("Public key required for verification")
        key = RSA.import_key(self.pub_pem)
        h = SHA256.new(message)
        verifier = pss.new(key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
