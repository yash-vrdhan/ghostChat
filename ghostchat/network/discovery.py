import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from nacl.signing import SigningKey

from ghostchat.crypto.keys import parse_verify_key_b64
from ghostchat.crypto.known_hosts import KnownHostsManager
from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.protocol.packets import DiscoverPacket


DISCOVERY_PORT = 54545
DISCOVERY_INTERVAL_SECONDS = 2
PEER_STALE_AFTER_SECONDS = 8


@dataclass
class Peer:
    peer_id: str
    username: str
    ip: str
    tcp_port: int
    enc_public_key_b64: str
    sign_public_key_b64: str
    last_seen: float
    is_trusted: bool = True
    trust_warning: Optional[str] = None


class DiscoveryService:
    def __init__(
        self,
        peer_id: str,
        username: str,
        tcp_port: int,
        enc_public_key_b64: str,
        sign_public_key_b64: str,
        sign_private: Optional[SigningKey] = None,
        known_hosts: Optional[KnownHostsManager] = None,
        on_peer_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self.peer_id = peer_id
        self.username = username
        self.tcp_port = tcp_port
        self.enc_public_key_b64 = enc_public_key_b64
        self.sign_public_key_b64 = sign_public_key_b64
        self.sign_private = sign_private
        self.known_hosts = known_hosts
        self.on_peer_change = on_peer_change

        self._stop_event = threading.Event()
        self._peers: Dict[str, Peer] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._broadcast_loop, daemon=True).start()
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()

    def peers(self) -> List[Peer]:
        with self._lock:
            return sorted(self._peers.values(), key=lambda p: p.username.lower())

    def _broadcast_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        while not self._stop_event.is_set():
            packet = DiscoverPacket(
                peer_id=self.peer_id,
                username=self.username,
                port=self.tcp_port,
                enc_public_key=self.enc_public_key_b64,
                sign_public_key=self.sign_public_key_b64,
            )
            if self.sign_private:
                packet.signature = sign_message(self.sign_private, packet.canonical_data())

            data = json.dumps(packet.to_dict()).encode("utf-8")
            try:
                sock.sendto(data, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            time.sleep(DISCOVERY_INTERVAL_SECONDS)

        sock.close()

    def _listen_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        try:
            sock.bind(("", DISCOVERY_PORT))
        except OSError as exc:
            print(f"[discovery] listener disabled: cannot bind UDP port {DISCOVERY_PORT} ({exc})")
            print("[discovery] another process may own that port without reuse enabled.")
            sock.close()
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue

            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue

            if payload.get("type") != "DISCOVER":
                continue

            packet = DiscoverPacket.from_dict(payload)
            if not packet.peer_id or packet.peer_id == self.peer_id:
                continue

            if not packet.enc_public_key or not packet.sign_public_key:
                continue

            # Verify signature if present
            if packet.signature:
                try:
                    verify_key = parse_verify_key_b64(packet.sign_public_key)
                    if not verify_signature(verify_key, packet.canonical_data(), packet.signature):
                        # Signature verification failed: spoofed / tampered packet
                        continue
                except Exception:
                    continue

            # TOFU check against known hosts
            is_trusted = True
            trust_warning = None
            if self.known_hosts:
                is_trusted, trust_warning = self.known_hosts.check_or_pin(
                    peer_id=packet.peer_id,
                    username=packet.username,
                    enc_public_key=packet.enc_public_key,
                    sign_public_key=packet.sign_public_key,
                )

            peer = Peer(
                peer_id=packet.peer_id,
                username=packet.username or "unknown",
                ip=addr[0],
                tcp_port=packet.port,
                enc_public_key_b64=packet.enc_public_key,
                sign_public_key_b64=packet.sign_public_key,
                last_seen=time.time(),
                is_trusted=is_trusted,
                trust_warning=trust_warning,
            )

            with self._lock:
                self._peers[packet.peer_id] = peer

            if self.on_peer_change:
                try:
                    self.on_peer_change()
                except Exception:
                    pass

        sock.close()

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            cutoff = time.time() - PEER_STALE_AFTER_SECONDS
            with self._lock:
                stale = [pid for pid, peer in self._peers.items() if peer.last_seen < cutoff]
                for pid in stale:
                    del self._peers[pid]
            if stale and self.on_peer_change:
                try:
                    self.on_peer_change()
                except Exception:
                    pass
            time.sleep(1)
