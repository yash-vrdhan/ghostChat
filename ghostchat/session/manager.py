import base64
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from nacl.secret import SecretBox

from ghostchat.network.discovery import Peer


class SessionManager:
    """Manages active chat thread state, pending chats queue, channels, and peer target resolution."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._chat_peer: Optional[Peer] = None
        # peer_id -> {"peer": Peer, "unread": int, "messages": List[str]}
        self._pending_chats: Dict[str, Dict[str, Any]] = {}

        # Channels state
        self._joined_channels: Set[str] = {"#general"}
        self._active_channel: Optional[str] = None
        self._channel_unread: Dict[str, int] = {}
        self._channel_messages: Dict[str, List[Dict[str, Any]]] = {"#general": []}

        # Peer message history: peer_id -> List[Dict[str, Any]]
        self._peer_messages: Dict[str, List[Dict[str, Any]]] = {}

    @property
    def chat_peer(self) -> Optional[Peer]:
        with self._lock:
            return self._chat_peer

    @property
    def active_channel(self) -> Optional[str]:
        with self._lock:
            return self._active_channel

    @property
    def joined_channels(self) -> List[str]:
        with self._lock:
            return sorted(self._joined_channels)

    def set_active_peer(self, peer: Optional[Peer]) -> Optional[Dict[str, Any]]:
        """Sets active chat peer and pops any pending unread messages."""
        with self._lock:
            self._chat_peer = peer
            if peer:
                self._active_channel = None
            if peer and peer.peer_id in self._pending_chats:
                return self._pending_chats.pop(peer.peer_id)
            return None

    def record_outgoing_peer_message(self, peer_id: str, username: str, text: str) -> None:
        """Record an outgoing message sent to a peer."""
        with self._lock:
            if peer_id not in self._peer_messages:
                self._peer_messages[peer_id] = []
            self._peer_messages[peer_id].append({
                "sender": username,
                "text": text,
                "timestamp": time.time(),
                "is_self": True,
            })

    def get_peer_messages(self, peer_id: str) -> List[Dict[str, Any]]:
        """Retrieve full conversation history for a peer."""
        with self._lock:
            return list(self._peer_messages.get(peer_id, []))

    def set_active_channel(self, channel: Optional[str]) -> None:
        """Sets active channel and clears unread badge."""
        with self._lock:
            if channel:
                channel = channel.lower()
                if not channel.startswith("#"):
                    channel = f"#{channel}"
                self._joined_channels.add(channel)
                self._chat_peer = None
                self._active_channel = channel
                self._channel_unread[channel] = 0
            else:
                self._active_channel = None

    def join_channel(self, channel: str) -> str:
        with self._lock:
            channel = channel.lower()
            if not channel.startswith("#"):
                channel = f"#{channel}"
            self._joined_channels.add(channel)
            if channel not in self._channel_messages:
                self._channel_messages[channel] = []
            return channel

    def leave_channel(self, channel: str) -> bool:
        with self._lock:
            channel = channel.lower()
            if not channel.startswith("#"):
                channel = f"#{channel}"
            if channel in self._joined_channels and channel != "#general":
                self._joined_channels.remove(channel)
                if self._active_channel == channel:
                    self._active_channel = None
                return True
            return False

    def get_channel_unread(self, channel: str) -> int:
        with self._lock:
            return self._channel_unread.get(channel.lower(), 0)

    def get_channel_messages(self, channel: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._channel_messages.get(channel.lower(), []))

    def record_incoming_group_message(
        self,
        channel: str,
        sender_username: str,
        text: str,
        timestamp: float,
        raw_content: Optional[str] = None,
        is_encrypted: bool = False,
    ) -> Dict[str, Any]:
        """Record an incoming group message into the channel history and update unread count."""
        with self._lock:
            channel = channel.lower()
            if not channel.startswith("#"):
                channel = f"#{channel}"

            msg_entry = {
                "channel": channel,
                "sender": sender_username,
                "text": text,
                "timestamp": timestamp,
                "raw_content": raw_content,
                "is_encrypted": is_encrypted,
            }

            if channel not in self._channel_messages:
                self._channel_messages[channel] = []
            self._channel_messages[channel].append(msg_entry)

            if self._active_channel == channel:
                return {"action": "active", "channel": channel, "entry": msg_entry}

            # If not currently viewing this channel, increment unread
            self._channel_unread[channel] = self._channel_unread.get(channel, 0) + 1
            return {
                "action": "queued",
                "channel": channel,
                "unread": self._channel_unread[channel],
                "entry": msg_entry,
            }

    def unlock_channel(self, channel: str, key: bytes) -> int:
        """Attempt to re-decrypt any locked messages in channel history using key. Returns number of unlocked messages."""
        with self._lock:
            channel = channel.lower()
            if not channel.startswith("#"):
                channel = f"#{channel}"
            unlocked = 0
            box = SecretBox(key)
            for entry in self._channel_messages.get(channel, []):
                if entry.get("is_encrypted") and entry.get("raw_content") and entry.get("text", "").startswith("[🔒"):
                    try:
                        decrypted = box.decrypt(base64.b64decode(entry["raw_content"])).decode("utf-8")
                        entry["text"] = decrypted
                        unlocked += 1
                    except Exception:
                        pass
            return unlocked

    def close_active_thread(self) -> None:
        with self._lock:
            self._chat_peer = None
            self._active_channel = None

    def get_pending_chats(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._pending_chats.values())

    def record_incoming_message(
        self,
        sender_peer_id: str,
        matched_peer: Optional[Peer],
        plaintext: str,
    ) -> Dict[str, Any]:
        """Record an incoming verified message and determine routing action.
        
        Returns a dict describing the outcome:
          - action: "active" | "auto_opened" | "queued" | "untracked"
          - unread_count: int
          - peer: Peer
        """
        with self._lock:
            sender_name = matched_peer.username if matched_peer else "peer"
            if sender_peer_id not in self._peer_messages:
                self._peer_messages[sender_peer_id] = []
            self._peer_messages[sender_peer_id].append({
                "sender": sender_name,
                "text": plaintext,
                "timestamp": time.time(),
                "is_self": False,
            })

            # Case 1: In an active thread with this exact sender
            if self._chat_peer and self._chat_peer.peer_id == sender_peer_id:
                return {"action": "active", "peer": self._chat_peer}

            # Case 2: No active thread at all (idle on welcome dashboard)
            if self._chat_peer is None and self._active_channel is None and matched_peer is not None:
                self._chat_peer = matched_peer
                self._pending_chats.pop(sender_peer_id, None)
                return {"action": "auto_opened", "peer": matched_peer}

            # Case 3: In an active thread with someone else or in a channel -> buffer as pending
            if matched_peer is not None:
                if sender_peer_id in self._pending_chats:
                    self._pending_chats[sender_peer_id]["unread"] += 1
                    self._pending_chats[sender_peer_id]["peer"] = matched_peer
                    self._pending_chats[sender_peer_id]["messages"].append(plaintext)
                else:
                    self._pending_chats[sender_peer_id] = {
                        "peer": matched_peer,
                        "unread": 1,
                        "messages": [plaintext],
                    }
                unread = self._pending_chats[sender_peer_id]["unread"]
                return {
                    "action": "queued",
                    "peer": matched_peer,
                    "unread_count": unread,
                    "active_peer": self._chat_peer,
                    "active_channel": self._active_channel,
                }

            return {"action": "untracked"}

    @staticmethod
    def resolve_target(peers: List[Peer], target_token: str) -> Union[Peer, List[Peer], None]:
        """Resolve a user-provided target token to a single Peer, a list of ambiguous Peers, or None.
        
        Supports:
          - 'username@port'
          - 'ip:port'
          - 'username' (exact match or list of duplicates)
        """
        if "@" in target_token:
            username, port_text = target_token.rsplit("@", 1)
            if port_text.isdigit():
                port = int(port_text)
                return next(
                    (p for p in peers if p.username == username and p.tcp_port == port),
                    None,
                )

        if ":" in target_token:
            host, port_text = target_token.rsplit(":", 1)
            if port_text.isdigit():
                port = int(port_text)
                return next((p for p in peers if p.ip == host and p.tcp_port == port), None)

        matches = [p for p in peers if p.username == target_token]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return matches
        return None
