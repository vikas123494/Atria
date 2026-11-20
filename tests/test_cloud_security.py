import base64
import hashlib
import hmac

from cloud.app.crypto import SecretBox
from cloud.app.security import signature_message, verify_hmac


def test_hmac_signature_matches_contract():
    secret = b"test-collector-secret"
    body = b'{"schema_version":"1.0"}'
    timestamp = "1795234327"
    nonce = "0123456789abcdef0123456789abcdef"
    message = signature_message("POST", "/v1/ingest", timestamp, nonce, body)
    signature = base64.b64encode(hmac.new(secret, message, hashlib.sha256).digest()).decode()
    assert verify_hmac(secret, "POST", "/v1/ingest", timestamp, nonce, body, signature)
    assert not verify_hmac(secret, "POST", "/v1/ingest", timestamp, nonce, b"tampered", signature)


def test_secret_box_encrypts_and_decrypts():
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    box = SecretBox(key)
    encrypted = box.encrypt(b"collector-secret")
    assert encrypted != b"collector-secret"
    assert box.decrypt(encrypted) == b"collector-secret"
