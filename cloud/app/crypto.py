"""At-rest encryption for collector HMAC keys.

HMAC verification requires the original key; a one-way Argon2 hash alone cannot
verify request MACs. This implementation encrypts keys with AES-GCM. Production
deployments should source the 32-byte key from a KMS/HSM.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretBox:
    def __init__(self, encoded_key: str):
        try:
            key = base64.urlsafe_b64decode(encoded_key.encode())
        except Exception as exc:
            raise ValueError("COLLECTOR_SECRET_ENCRYPTION_KEY must be URL-safe base64") from exc
        if len(key) != 32:
            raise ValueError("COLLECTOR_SECRET_ENCRYPTION_KEY must decode to 32 bytes")
        self._aes = AESGCM(key)

    @classmethod
    def from_environment(cls):
        value = os.getenv("COLLECTOR_SECRET_ENCRYPTION_KEY", "")
        if not value:
            raise RuntimeError("COLLECTOR_SECRET_ENCRYPTION_KEY is required")
        return cls(value)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext, b"veilops-collector-secret-v1")

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 29:
            raise ValueError("Invalid encrypted collector secret")
        return self._aes.decrypt(ciphertext[:12], ciphertext[12:], b"veilops-collector-secret-v1")


class ReceiptSigner:
    """Ed25519 receipt signer; private key is a base64-encoded 32-byte seed."""
    def __init__(self, encoded_seed: str):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        seed = base64.urlsafe_b64decode(encoded_seed.encode())
        if len(seed) != 32:
            raise ValueError("SAAS_ED25519_PRIVATE_KEY must decode to 32 bytes")
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self._public_bytes = self._private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @classmethod
    def from_environment(cls):
        import os
        value = os.getenv("SAAS_ED25519_PRIVATE_KEY", "")
        if not value:
            raise RuntimeError("SAAS_ED25519_PRIVATE_KEY is required")
        return cls(value)

    def sign(self, message: bytes) -> str:
        import base64
        return base64.b64encode(self._private.sign(message)).decode("ascii")

    def public_key_b64(self) -> str:
        import base64
        return base64.b64encode(self._public_bytes).decode("ascii")
