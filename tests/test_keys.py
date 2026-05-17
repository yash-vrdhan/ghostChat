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
