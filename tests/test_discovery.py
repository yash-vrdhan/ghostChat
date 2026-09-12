from nacl.signing import SigningKey

from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.protocol.packets import DiscoverPacket


def test_discovery_packet_signing_and_verification() -> None:
    sk = SigningKey.generate()
    vk = sk.verify_key

    packet = DiscoverPacket(
        peer_id="p-alice",
        username="alice",
        port=5001,
        enc_public_key="enc-key-b64",
        sign_public_key="sign-key-b64",
    )
    packet.signature = sign_message(sk, packet.canonical_data())

    # Verify signature passes
    assert verify_signature(vk, packet.canonical_data(), packet.signature) is True

    # Tampered username or port fails verification
    tampered_packet = DiscoverPacket(
        peer_id="p-alice",
        username="impersonator",
        port=5001,
        enc_public_key="enc-key-b64",
        sign_public_key="sign-key-b64",
        signature=packet.signature,
    )
    assert verify_signature(vk, tampered_packet.canonical_data(), tampered_packet.signature) is False
