import asyncio
import base64
import time
import uuid
from unittest.mock import MagicMock

import nacl.signing
from nacl.secret import SecretBox

from ghostchat.crypto.keys import parse_verify_key_b64
from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.main import GhostChatApp
from ghostchat.network.discovery import Peer
from ghostchat.network.gossip import (
    GossipService,
    SeenMessageCache,
    derive_channel_key,
)
from ghostchat.protocol.packets import (
    ChannelAnnouncePacket,
    GroupMessagePacket,
)
from ghostchat.ui.app import GhostChatTUIApp


def test_gossip_packet_signing_and_verification() -> None:
    sign_key = nacl.signing.SigningKey.generate()
    verify_key = sign_key.verify_key
    pub_b64 = base64.b64encode(verify_key.encode()).decode("utf-8")

    packet = GroupMessagePacket(
        channel="#general",
        message_id=str(uuid.uuid4()),
        sender_username="alice",
        sender_peer_id="alice_node_01",
        sender_sign_public_key=pub_b64,
        timestamp=time.time(),
        content="Hello gossip mesh!",
        is_encrypted=False,
    )
    packet.signature = sign_message(sign_key, packet.canonical_data())

    # Valid verification
    vk = parse_verify_key_b64(packet.sender_sign_public_key)
    assert verify_signature(vk, packet.canonical_data(), packet.signature) is True

    # Tampered content must fail
    tampered_canonical = packet.canonical_data().replace("Hello", "Tampered")
    assert verify_signature(vk, tampered_canonical, packet.signature) is False


def test_gossip_seen_cache_deduplication() -> None:
    cache = SeenMessageCache(max_size=3)
    msg1 = "uuid-1"
    msg2 = "uuid-2"
    msg3 = "uuid-3"
    msg4 = "uuid-4"

    assert cache.mark_seen(msg1) is True
    assert cache.mark_seen(msg1) is False  # Duplicate rejected
    assert cache.is_seen(msg1) is True

    assert cache.mark_seen(msg2) is True
    assert cache.mark_seen(msg3) is True

    # Cache capacity exceeded -> oldest (msg1) evicted
    assert cache.mark_seen(msg4) is True
    assert cache.is_seen(msg1) is False
    assert cache.is_seen(msg4) is True


def test_keyed_channel_encryption_and_decryption() -> None:
    channel = "#secret-ops"
    passphrase = "UltraSecurePassword42!"

    key = derive_channel_key(channel, passphrase)
    assert len(key) == 32

    box = SecretBox(key)
    plaintext = "Confidential deployment instructions."
    encrypted = box.encrypt(plaintext.encode("utf-8"))
    b64_cipher = base64.b64encode(encrypted).decode("utf-8")

    # Decrypt with correct key
    decrypted = box.decrypt(base64.b64decode(b64_cipher)).decode("utf-8")
    assert decrypted == plaintext

    # Wrong passphrase must fail decryption
    wrong_key = derive_channel_key(channel, "WrongPassword!")
    wrong_box = SecretBox(wrong_key)
    try:
        wrong_box.decrypt(base64.b64decode(b64_cipher))
        assert False, "Should have raised CryptoError"
    except Exception:
        pass


def test_gossip_service_publish_and_relay() -> None:
    mock_transport = MagicMock()
    mock_discovery = MagicMock()

    peer_bob = Peer(
        peer_id="bob_id",
        username="bob",
        ip="127.0.0.1",
        tcp_port=5002,
        enc_public_key_b64="key",
        sign_public_key_b64="key",
        last_seen=time.time(),
    )
    mock_discovery.peers.return_value = [peer_bob]

    delivered_messages = []

    def on_msg(pkt: GroupMessagePacket, text: str) -> None:
        delivered_messages.append((pkt, text))

    sign_key = nacl.signing.SigningKey.generate()
    pub_b64 = base64.b64encode(sign_key.verify_key.encode()).decode("utf-8")

    gossip = GossipService(
        local_peer_id="alice_id",
        username="alice",
        sign_public_key_b64=pub_b64,
        sign_private=sign_key,
        transport=mock_transport,
        discovery=mock_discovery,
        on_group_message=on_msg,
    )

    # Publish message to #general
    pkt = gossip.publish("#general", "Broadcast across LAN!")
    assert pkt is not None
    assert pkt.channel == "#general"
    assert len(delivered_messages) == 1
    assert delivered_messages[0][1] == "Broadcast across LAN!"

    # Simulate receiving a forwarded packet from Bob with TTL=5
    incoming_pkt = GroupMessagePacket(
        channel="#general",
        message_id="unique-msg-bob",
        sender_username="bob",
        sender_peer_id="bob_id",
        sender_sign_public_key=pub_b64,
        timestamp=time.time(),
        content="Relayed from Bob",
        ttl=5,
        hop_count=0,
    )
    incoming_pkt.signature = sign_message(sign_key, incoming_pkt.canonical_data())

    gossip.handle_group_packet(incoming_pkt.to_dict())

    # Should be delivered locally
    assert len(delivered_messages) == 2
    assert delivered_messages[1][1] == "Relayed from Bob"

    # Duplicate incoming packet must be suppressed
    gossip.handle_group_packet(incoming_pkt.to_dict())
    assert len(delivered_messages) == 2


def test_channel_announce_and_membership_tracking() -> None:
    mock_transport = MagicMock()
    mock_discovery = MagicMock()

    gossip = GossipService(
        local_peer_id="alice_id",
        username="alice",
        sign_public_key_b64="key",
        sign_private=None,
        transport=mock_transport,
        discovery=mock_discovery,
    )

    assert gossip.get_channel_members_count("#dev-team") == 1  # Alice

    ann_join = ChannelAnnouncePacket(
        channel="#dev-team",
        sender_username="bob",
        sender_peer_id="bob_id",
        action="JOIN",
        timestamp=time.time(),
    )
    gossip.handle_channel_announce(ann_join.to_dict())
    assert gossip.get_channel_members_count("#dev-team") == 2  # Alice + Bob

    ann_leave = ChannelAnnouncePacket(
        channel="#dev-team",
        sender_username="bob",
        sender_peer_id="bob_id",
        action="LEAVE",
        timestamp=time.time(),
    )
    gossip.handle_channel_announce(ann_leave.to_dict())
    assert gossip.get_channel_members_count("#dev-team") == 1


def test_tui_channel_thread_open_and_messaging(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr("ghostchat.crypto.keys.KEY_ROOT_DIR", tmp_path)
        backend = GhostChatApp(username="test_alice", port=59994)
        tui_app = GhostChatTUIApp(backend=backend)

        async with tui_app.run_test(size=(100, 30)) as pilot:
            # Check channel list in sidebar
            assert tui_app.query_one("#channel-list") is not None

            # Open #general channel thread
            tui_app.open_channel_thread("#general")
            assert backend.session.active_channel == "#general"

            # Check header
            header_text = str(tui_app.query_one("#chat-header").render())
            assert "#general" in header_text

            # Send group message in channel thread
            input_box = tui_app.query_one("#message-input")
            input_box.value = "Testing channel broadcast"
            await pilot.press("enter")

            # Verify recorded in session history
            history = backend.session.get_channel_messages("#general")
            assert len(history) >= 1
            assert history[-1]["text"] == "Testing channel broadcast"

    asyncio.run(run())
