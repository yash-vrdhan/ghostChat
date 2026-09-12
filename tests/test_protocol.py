import socket
import pytest

from ghostchat.protocol.packets import (
    AckPacket,
    DiscoverPacket,
    FramingCodec,
    MAX_PACKET_SIZE,
    MessagePacket,
)


def test_framing_codec_round_trip() -> None:
    sock_a, sock_b = socket.socketpair()
    try:
        payload = b'{"hello": "world", "status": "ok"}'
        framed = FramingCodec.encode_frame(payload)
        sock_a.sendall(framed)

        received = FramingCodec.read_frame(sock_b)
        assert received == payload
    finally:
        sock_a.close()
        sock_b.close()


def test_framing_codec_rejects_oversized_payload() -> None:
    oversized = b"x" * (MAX_PACKET_SIZE + 1)
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        FramingCodec.encode_frame(oversized)


def test_framing_codec_detects_oversized_incoming_header() -> None:
    sock_a, sock_b = socket.socketpair()
    try:
        # Craft a header claiming length > MAX_PACKET_SIZE
        import struct
        malicious_header = struct.pack("!I", MAX_PACKET_SIZE + 500)
        sock_a.sendall(malicious_header)

        with pytest.raises(ValueError, match="exceeds maximum allowed size"):
            FramingCodec.read_frame(sock_b)
    finally:
        sock_a.close()
        sock_b.close()


def test_packet_dataclass_conversions() -> None:
    disc = DiscoverPacket(
        peer_id="p1",
        username="alice",
        port=5001,
        enc_public_key="enc123",
        sign_public_key="sign123",
        signature="sig123",
    )
    d_dict = disc.to_dict()
    disc2 = DiscoverPacket.from_dict(d_dict)
    assert disc == disc2
    assert disc.canonical_data() == "p1:alice:5001:enc123:sign123"

    msg = MessagePacket(
        sender="alice",
        sender_peer_id="p1",
        sender_enc_public_key="enc1",
        sender_sign_public_key="sign1",
        ciphertext="c1",
        signature="s1",
        message_id="m1",
    )
    msg2 = MessagePacket.from_dict(msg.to_dict())
    assert msg == msg2

    ack = AckPacket(message_id="m1", sender_peer_id="p1")
    ack2 = AckPacket.from_dict(ack.to_dict())
    assert ack == ack2
