import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def sign_message(signing_key: SigningKey, message: str) -> str:
    sig = signing_key.sign(message.encode("utf-8")).signature
    return base64.b64encode(sig).decode("ascii")


def verify_signature(verify_key: VerifyKey, message: str, signature_b64: str) -> bool:
    try:
        verify_key.verify(message.encode("utf-8"), base64.b64decode(signature_b64))
        return True
    except BadSignatureError:
        return False
