import os
import stat
from pathlib import Path

from ghostchat.crypto import keys


def test_keys_persist_for_same_profile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(keys, "KEY_ROOT_DIR", tmp_path)

    first = keys.load_or_create_keys(profile="alice")
    second = keys.load_or_create_keys(profile="alice")

    assert bytes(first.enc_private) == bytes(second.enc_private)
    assert bytes(first.sign_private) == bytes(second.sign_private)
    assert first.fingerprint == second.fingerprint


def test_keys_are_isolated_between_profiles(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(keys, "KEY_ROOT_DIR", tmp_path)

    alice = keys.load_or_create_keys(profile="alice")
    bob = keys.load_or_create_keys(profile="bob")

    assert bytes(alice.enc_private) != bytes(bob.enc_private)
    assert bytes(alice.sign_private) != bytes(bob.sign_private)
    assert alice.fingerprint != bob.fingerprint


def test_key_files_and_directory_have_secure_permissions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(keys, "KEY_ROOT_DIR", tmp_path)

    keys.load_or_create_keys(profile="secure_alice")
    profile_dir = tmp_path / "secure_alice"
    enc_path = profile_dir / keys.ENC_PRIVATE_FILE
    sign_path = profile_dir / keys.SIGN_PRIVATE_FILE

    # Check directory permissions (0700: rwx------)
    dir_mode = stat.S_IMODE(os.stat(profile_dir).st_mode)
    assert dir_mode == 0o700, f"Expected 0700 dir mode, got {oct(dir_mode)}"

    # Check private key file permissions (0600: rw-------)
    enc_mode = stat.S_IMODE(os.stat(enc_path).st_mode)
    assert enc_mode == 0o600, f"Expected 0600 file mode, got {oct(enc_mode)}"

    sign_mode = stat.S_IMODE(os.stat(sign_path).st_mode)
    assert sign_mode == 0o600, f"Expected 0600 file mode, got {oct(sign_mode)}"
