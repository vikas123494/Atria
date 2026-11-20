"""Generate independent local-demo secrets without writing them to disk."""
import base64
import secrets


def encoded_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


if __name__ == "__main__":
    print("COLLECTOR_SECRET_ENCRYPTION_KEY=" + encoded_key())
    print("SAAS_ED25519_PRIVATE_KEY=" + encoded_key())
    print("DASHBOARD_JWT_SECRET=" + secrets.token_urlsafe(48))
