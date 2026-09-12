import threading
from typing import Any, Dict, List, Optional, Tuple, Union

from ghostchat.network.discovery import Peer


class SessionManager:
    """Manages active chat thread state, pending chats queue, and peer target resolution."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._chat_peer: Optional[Peer] = None
        # peer_id -> {"peer": Peer, "unread": int, "messages": List[str]}
        self._pending_chats: Dict[str, Dict[str, Any]] = {}

    @property
    def chat_peer(self) -> Optional[Peer]:
        with self._lock:
            return self._chat_peer

    def set_active_peer(self, peer: Optional[Peer]) -> Optional[Dict[str, Any]]:
        """Sets active chat peer and pops any pending unread messages."""
        with self._lock:
            self._chat_peer = peer
            if peer and peer.peer_id in self._pending_chats:
                return self._pending_chats.pop(peer.peer_id)
            return None

    def close_active_thread(self) -> None:
        with self._lock:
            self._chat_peer = None

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
            # Case 1: In an active thread with this exact sender
            if self._chat_peer and self._chat_peer.peer_id == sender_peer_id:
                return {"action": "active", "peer": self._chat_peer}

            # Case 2: No active thread -> auto-open thread if peer is known
            if self._chat_peer is None and matched_peer is not None:
                self._chat_peer = matched_peer
                self._pending_chats.pop(sender_peer_id, None)
                return {"action": "auto_opened", "peer": matched_peer}

            # Case 3: In an active thread with someone else -> buffer as pending
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
