import base64
from dataclasses import dataclass
from pathlib import Path

from nacl.encoding import RawEncoder
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey


KEY_ROOT_DIR = Path.home() / ".ghostchat"
ENC_PRIVATE_FILE = "enc_private.key"
SIGN_PRIVATE_FILE = "sign_private.key"


@dataclass
class NodeKeys:
    enc_private: PrivateKey
    enc_public: PublicKey
    sign_private: SigningKey
    sign_public: VerifyKey

    @property
    def enc_public_b64(self) -> str:
        return base64.b64encode(bytes(self.enc_public)).decode("ascii")

    @property
    def sign_public_b64(self) -> str:
        return base64.b64encode(bytes(self.sign_public)).decode("ascii")

    @property
    def fingerprint(self) -> str:
        raw = bytes(self.sign_public)
        return base64.b16encode(raw[:8]).decode("ascii").lower()


def _write_private_key(path: Path, raw: bytes) -> None:
    path.write_text(base64.b64encode(raw).decode("ascii"), encoding="utf-8")


def _read_private_key(path: Path) -> bytes:
    return base64.b64decode(path.read_text(encoding="utf-8").strip())


def load_or_create_keys(profile: str = "default") -> NodeKeys:
    safe_profile = "".join(c for c in profile if c.isalnum() or c in ("-", "_")).strip("_-")
    if not safe_profile:
        safe_profile = "default"
    key_dir = KEY_ROOT_DIR / safe_profile
    key_dir.mkdir(parents=True, exist_ok=True)

    enc_path = key_dir / ENC_PRIVATE_FILE
    sign_path = key_dir / SIGN_PRIVATE_FILE

    if enc_path.exists():
        enc_private = PrivateKey(_read_private_key(enc_path), encoder=RawEncoder)
    else:
        enc_private = PrivateKey.generate()
        _write_private_key(enc_path, bytes(enc_private))

    if sign_path.exists():
        sign_private = SigningKey(_read_private_key(sign_path), encoder=RawEncoder)
    else:
        sign_private = SigningKey.generate()
        _write_private_key(sign_path, bytes(sign_private))

    return NodeKeys(
        enc_private=enc_private,
        enc_public=enc_private.public_key,
        sign_private=sign_private,
        sign_public=sign_private.verify_key,
    )


def parse_public_key_b64(public_key_b64: str) -> PublicKey:
    return PublicKey(base64.b64decode(public_key_b64))


def parse_verify_key_b64(verify_key_b64: str) -> VerifyKey:
    return VerifyKey(base64.b64decode(verify_key_b64))
