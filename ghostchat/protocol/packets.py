import json
import socket
import struct
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


MAX_PACKET_SIZE = 65536  # 64 KB guardrail against unbounded buffering / DoS


class FramingCodec:
    """Length-prefixed binary framing codec.
    
    Frames are formatted as:
      [4 bytes: big-endian uint32 payload length][payload bytes]
    """

    @staticmethod
    def encode_frame(payload_bytes: bytes) -> bytes:
        if len(payload_bytes) > MAX_PACKET_SIZE:
            raise ValueError(
                f"Payload size {len(payload_bytes)} exceeds maximum limit of {MAX_PACKET_SIZE} bytes."
            )
        header = struct.pack("!I", len(payload_bytes))
        return header + payload_bytes

    @staticmethod
    def read_exact(sock: socket.socket, num_bytes: int) -> bytes:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed while reading frame bytes")
            buf.extend(chunk)
        return bytes(buf)

    @classmethod
    def read_frame(cls, sock: socket.socket, max_size: int = MAX_PACKET_SIZE) -> bytes:
        header = cls.read_exact(sock, 4)
        (length,) = struct.unpack("!I", header)
        if length > max_size:
            raise ValueError(
                f"Incoming frame length {length} exceeds maximum allowed size of {max_size} bytes."
            )
        return cls.read_exact(sock, length)


def canonical_discovery_string(
    peer_id: str,
    username: str,
    port: int,
    enc_public_key: str,
    sign_public_key: str,
) -> str:
    """Generate deterministic canonical representation of peer identity for signing/verifying."""
    return f"{peer_id}:{username}:{port}:{enc_public_key}:{sign_public_key}"


@dataclass
class DiscoverPacket:
    peer_id: str
    username: str
    port: int
    enc_public_key: str
    sign_public_key: str
    signature: str = ""
    type: str = "DISCOVER"

    def canonical_data(self) -> str:
        return canonical_discovery_string(
            self.peer_id,
            self.username,
            self.port,
            self.enc_public_key,
            self.sign_public_key,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoverPacket":
        return cls(
            peer_id=str(data.get("peer_id", "")),
            username=str(data.get("username", "")),
            port=int(data.get("port", 0)),
            enc_public_key=str(data.get("enc_public_key", "")),
            sign_public_key=str(data.get("sign_public_key", "")),
            signature=str(data.get("signature", "")),
            type=str(data.get("type", "DISCOVER")),
        )


@dataclass
class MessagePacket:
    sender: str
    sender_peer_id: str
    sender_enc_public_key: str
    sender_sign_public_key: str
    ciphertext: str
    signature: str
    message_id: str
    type: str = "MESSAGE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MessagePacket":
        return cls(
            sender=str(data.get("sender", "unknown")),
            sender_peer_id=str(data.get("sender_peer_id", "")),
            sender_enc_public_key=str(data.get("sender_enc_public_key", "")),
            sender_sign_public_key=str(data.get("sender_sign_public_key", "")),
            ciphertext=str(data.get("ciphertext", "")),
            signature=str(data.get("signature", "")),
            message_id=str(data.get("message_id", "")),
            type=str(data.get("type", "MESSAGE")),
        )


@dataclass
class AckPacket:
    message_id: str
    sender_peer_id: str
    type: str = "ACK"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AckPacket":
        return cls(
            message_id=str(data.get("message_id", "")),
            sender_peer_id=str(data.get("sender_peer_id", "")),
            type=str(data.get("type", "ACK")),
        )


def canonical_group_message_string(
    channel: str,
    message_id: str,
    sender_peer_id: str,
    timestamp: float,
    content: str,
) -> str:
    """Deterministic string representation of group message for Ed25519 signing/verification."""
    return f"{channel}:{message_id}:{sender_peer_id}:{timestamp:.3f}:{content}"


@dataclass
class GroupMessagePacket:
    channel: str
    message_id: str
    sender_username: str
    sender_peer_id: str
    sender_sign_public_key: str
    timestamp: float
    content: str
    is_encrypted: bool = False
    ttl: int = 5
    hop_count: int = 0
    signature: str = ""
    type: str = "GROUP_MESSAGE"

    def canonical_data(self) -> str:
        return canonical_group_message_string(
            self.channel,
            self.message_id,
            self.sender_peer_id,
            self.timestamp,
            self.content,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GroupMessagePacket":
        return cls(
            channel=str(data.get("channel", "#general")),
            message_id=str(data.get("message_id", "")),
            sender_username=str(data.get("sender_username", "unknown")),
            sender_peer_id=str(data.get("sender_peer_id", "")),
            sender_sign_public_key=str(data.get("sender_sign_public_key", "")),
            timestamp=float(data.get("timestamp", 0.0)),
            content=str(data.get("content", "")),
            is_encrypted=bool(data.get("is_encrypted", False)),
            ttl=int(data.get("ttl", 5)),
            hop_count=int(data.get("hop_count", 0)),
            signature=str(data.get("signature", "")),
            type=str(data.get("type", "GROUP_MESSAGE")),
        )


@dataclass
class ChannelAnnouncePacket:
    channel: str
    sender_username: str
    sender_peer_id: str
    action: str  # "JOIN" or "LEAVE"
    timestamp: float
    type: str = "CHANNEL_ANNOUNCE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChannelAnnouncePacket":
        return cls(
            channel=str(data.get("channel", "#general")),
            sender_username=str(data.get("sender_username", "unknown")),
            sender_peer_id=str(data.get("sender_peer_id", "")),
            action=str(data.get("action", "JOIN")),
            timestamp=float(data.get("timestamp", 0.0)),
            type=str(data.get("type", "CHANNEL_ANNOUNCE")),
        )

