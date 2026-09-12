import base64
import hashlib
import json
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import nacl.exceptions
from nacl.secret import SecretBox
from nacl.signing import SigningKey

from ghostchat.crypto.keys import parse_verify_key_b64
from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.network.discovery import DiscoveryService, Peer
from ghostchat.network.transport import TransportService
from ghostchat.protocol.packets import (
    ChannelAnnouncePacket,
    GroupMessagePacket,
)


def derive_channel_key(channel: str, passphrase: str) -> bytes:
    """Derive a deterministic 32-byte symmetric key for a private channel."""
    salt = channel.lower().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations=10000, dklen=32)


class SeenMessageCache:
    """Thread-safe bounded LRU-style cache to suppress duplicate gossip packets."""

    def __init__(self, max_size: int = 5000) -> None:
        self._max_size = max_size
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_seen(self, message_id: str) -> bool:
        with self._lock:
            return message_id in self._seen

    def mark_seen(self, message_id: str) -> bool:
        """Mark message_id as seen. Returns True if newly added, False if already seen."""
        with self._lock:
            if message_id in self._seen:
                return False
            self._seen[message_id] = time.time()
            if len(self._seen) > self._max_size:
                oldest_key = next(iter(self._seen))
                del self._seen[oldest_key]
            return True


class GossipService:
    """Epidemic gossip mesh protocol service for multi-party group channels."""

    def __init__(
        self,
        local_peer_id: str,
        username: str,
        sign_public_key_b64: str,
        sign_private: Optional[SigningKey],
        transport: TransportService,
        discovery: DiscoveryService,
        on_group_message: Optional[Callable[[GroupMessagePacket, str], None]] = None,
        on_channel_change: Optional[Callable[[str, int], None]] = None,
    ) -> None:
        self.local_peer_id = local_peer_id
        self.username = username
        self.sign_public_key_b64 = sign_public_key_b64
        self.sign_private = sign_private
        self.transport = transport
        self.discovery = discovery
        self.on_group_message = on_group_message
        self.on_channel_change = on_channel_change

        self.seen_cache = SeenMessageCache(max_size=5000)
        self.channel_keys: Dict[str, bytes] = {}
        self.channel_members: Dict[str, Set[str]] = {"#general": set()}
        self._lock = threading.RLock()

    def set_channel_key(self, channel: str, passphrase: str) -> None:
        key = derive_channel_key(channel, passphrase)
        with self._lock:
            self.channel_keys[channel.lower()] = key

    def get_channel_members_count(self, channel: str) -> int:
        with self._lock:
            members = self.channel_members.get(channel.lower(), set())
            return len(members) + 1  # includes self

    def publish(self, channel: str, text: str) -> Optional[GroupMessagePacket]:
        """Publish a group message to a channel and initiate gossip propagation."""
        channel = channel.lower()
        if not channel.startswith("#"):
            channel = f"#{channel}"

        message_id = str(uuid.uuid4())
        now = time.time()

        content = text
        is_encrypted = False

        with self._lock:
            if channel in self.channel_keys:
                box = SecretBox(self.channel_keys[channel])
                encrypted = box.encrypt(text.encode("utf-8"))
                content = base64.b64encode(encrypted).decode("utf-8")
                is_encrypted = True

        packet = GroupMessagePacket(
            channel=channel,
            message_id=message_id,
            sender_username=self.username,
            sender_peer_id=self.local_peer_id,
            sender_sign_public_key=self.sign_public_key_b64,
            timestamp=now,
            content=content,
            is_encrypted=is_encrypted,
            ttl=5,
            hop_count=0,
        )

        if self.sign_private:
            packet.signature = sign_message(self.sign_private, packet.canonical_data())

        # Mark seen locally
        self.seen_cache.mark_seen(message_id)

        # Notify local listener
        if self.on_group_message:
            try:
                self.on_group_message(packet, text)
            except Exception:
                pass

        # Relay to peers over gossip mesh
        self._relay_packet(packet.to_dict())
        return packet

    def handle_group_packet(self, packet_data: dict) -> None:
        """Process an incoming gossip packet, verify authenticity, deliver, and relay."""
        packet = GroupMessagePacket.from_dict(packet_data)

        # 1. Deduplication check
        if not self.seen_cache.mark_seen(packet.message_id):
            return  # Already seen and processed

        # 2. Cryptographic signature verification
        if packet.signature and packet.sender_sign_public_key:
            try:
                verify_key = parse_verify_key_b64(packet.sender_sign_public_key)
                if not verify_signature(verify_key, packet.canonical_data(), packet.signature):
                    return  # Tampered or forged message
            except Exception:
                return  # Malformed signature or key

        # 3. Decrypt or extract payload
        decoded_text = packet.content
        if packet.is_encrypted:
            channel_key = None
            with self._lock:
                channel_key = self.channel_keys.get(packet.channel.lower())

            if channel_key:
                try:
                    box = SecretBox(channel_key)
                    raw_cipher = base64.b64decode(packet.content)
                    decrypted_bytes = box.decrypt(raw_cipher)
                    decoded_text = decrypted_bytes.decode("utf-8")
                except Exception:
                    decoded_text = "[🔒 Decryption failed: invalid channel key]"
            else:
                decoded_text = f"[🔒 Encrypted message on {packet.channel}: key required to view]"

        # 4. Deliver to local UI/Session callback
        if self.on_group_message:
            try:
                self.on_group_message(packet, decoded_text)
            except Exception:
                pass

        # 5. Flood forwarding (relay if TTL allows)
        if packet.ttl > 1:
            relayed = packet.to_dict()
            relayed["ttl"] = packet.ttl - 1
            relayed["hop_count"] = packet.hop_count + 1
            self._relay_packet(relayed, exclude_peer_id=packet.sender_peer_id)

    def announce_channel(self, channel: str, action: str = "JOIN") -> None:
        """Announce joining or leaving a channel to the mesh."""
        channel = channel.lower()
        if not channel.startswith("#"):
            channel = f"#{channel}"

        packet = ChannelAnnouncePacket(
            channel=channel,
            sender_username=self.username,
            sender_peer_id=self.local_peer_id,
            action=action,
            timestamp=time.time(),
        )
        self._relay_packet(packet.to_dict())

    def handle_channel_announce(self, packet_data: dict) -> None:
        """Track member counts across channels based on announcements."""
        packet = ChannelAnnouncePacket.from_dict(packet_data)
        channel = packet.channel.lower()

        with self._lock:
            if channel not in self.channel_members:
                self.channel_members[channel] = set()

            if packet.action == "JOIN":
                self.channel_members[channel].add(packet.sender_peer_id)
            elif packet.action == "LEAVE":
                self.channel_members[channel].discard(packet.sender_peer_id)

            member_count = len(self.channel_members[channel]) + 1

        if self.on_channel_change:
            try:
                self.on_channel_change(channel, member_count)
            except Exception:
                pass

    def _relay_packet(self, packet_dict: dict, exclude_peer_id: Optional[str] = None) -> int:
        """Broadcast packet to all currently discovered peers on LAN."""
        peers = self.discovery.peers()
        relayed_count = 0

        for peer in peers:
            if peer.peer_id == self.local_peer_id:
                continue
            if exclude_peer_id and peer.peer_id == exclude_peer_id:
                continue

            # Send asynchronously without waiting for individual TCP ACK
            threading.Thread(
                target=self.transport.send_packet,
                args=(peer.peer_id, peer.ip, peer.tcp_port, packet_dict, False),
                daemon=True,
            ).start()
            relayed_count += 1

        return relayed_count
