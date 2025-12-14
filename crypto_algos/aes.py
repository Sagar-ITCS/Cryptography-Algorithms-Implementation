"""
AES utilities.
Provides AES-CBC (PKCS7) and AES-GCM (AEAD) helper wrapper classes.
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple
import os

BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding (empty)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


class AESCipher:
    """Simple AES helper supporting CBC+PKCS7 and GCM.

    Usage:
        key = AESCipher.generate_key(32)
        cipher = AESCipher(key)
        ct = cipher.encrypt_cbc(b"hello")
        pt = cipher.decrypt_cbc(ct)
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16,24, or 32 bytes")
        self.key = key

    @staticmethod
    def generate_key(length: int = 32) -> bytes:
        if length not in (16, 24, 32):
            raise ValueError("Key size must be 16,24,32 bytes")
        return get_random_bytes(length)

    # ---------- CBC ----------
    def encrypt_cbc(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(_pkcs7_pad(plaintext))
        return iv + ct

    def decrypt_cbc(self, iv_and_ct: bytes) -> bytes:
        if len(iv_and_ct) < BLOCK_SIZE:
            raise ValueError("Ciphertext too short")
        iv = iv_and_ct[:BLOCK_SIZE]
        ct = iv_and_ct[BLOCK_SIZE:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt_padded = cipher.decrypt(ct)
        return _pkcs7_unpad(pt_padded)

    # ---------- GCM (authenticated) ----------
    def encrypt_gcm(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        # return nonce + tag + ciphertext
        return cipher.nonce + tag + ct

    def decrypt_gcm(self, nonce_tag_ct: bytes, aad: bytes | None = None) -> bytes:
        if len(nonce_tag_ct) < 12 + 16:
            raise ValueError("Data too short for GCM")
        nonce = nonce_tag_ct[:12]
        tag = nonce_tag_ct[12:28]
        ct = nonce_tag_ct[28:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt


# small helper to save/load raw keys

def save_key(path: str, key: bytes):
    with open(path, "wb") as f:
        f.write(key)


def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
