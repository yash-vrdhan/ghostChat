from pathlib import Path

from ghostchat.crypto.known_hosts import KnownHostsManager


def test_known_hosts_pins_and_verifies_identity(tmp_path: Path) -> None:
    mgr = KnownHostsManager(tmp_path)

    # 1. First encounter: trusted and pinned
    trusted, warning = mgr.check_or_pin(
        peer_id="peer-bob",
        username="bob",
        enc_public_key="enc_key_1",
        sign_public_key="sign_key_1",
    )
    assert trusted is True
    assert warning is None

    # 2. Subsequent encounter with same keys: trusted
    trusted, warning = mgr.check_or_pin(
        peer_id="peer-bob",
        username="bob",
        enc_public_key="enc_key_1",
        sign_public_key="sign_key_1",
    )
    assert trusted is True
    assert warning is None

    # 3. Encounter with altered keys: flagged as untrusted MITM warning
    trusted, warning = mgr.check_or_pin(
        peer_id="peer-bob",
        username="bob",
        enc_public_key="malicious_enc_key",
        sign_public_key="sign_key_1",
    )
    assert trusted is False
    assert warning is not None
    assert "SECURITY ALERT" in warning


def test_known_hosts_persists_across_restarts(tmp_path: Path) -> None:
    mgr1 = KnownHostsManager(tmp_path)
    mgr1.check_or_pin(
        peer_id="peer-charlie",
        username="charlie",
        enc_public_key="enc_c",
        sign_public_key="sign_c",
    )

    # Re-instantiate from same directory
    mgr2 = KnownHostsManager(tmp_path)
    record = mgr2.get_host("peer-charlie")
    assert record is not None
    assert record["username"] == "charlie"
    assert record["enc_public_key"] == "enc_c"
