import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List


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


class DiscoveryService:
    def __init__(
        self,
        peer_id: str,
        username: str,
        tcp_port: int,
        enc_public_key_b64: str,
        sign_public_key_b64: str,
    ) -> None:
        self.peer_id = peer_id
        self.username = username
        self.tcp_port = tcp_port
        self.enc_public_key_b64 = enc_public_key_b64
        self.sign_public_key_b64 = sign_public_key_b64
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
            packet = {
                "type": "DISCOVER",
                "peer_id": self.peer_id,
                "username": self.username,
                "port": self.tcp_port,
                "enc_public_key": self.enc_public_key_b64,
                "sign_public_key": self.sign_public_key_b64,
            }
            data = json.dumps(packet).encode("utf-8")
            try:
                sock.sendto(data, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            time.sleep(DISCOVERY_INTERVAL_SECONDS)

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
            print("[discovery] another process may own that port without reuse enabled; restart all GhostChat nodes after updating.")
            sock.close()
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue

            try:
                packet = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue

            if packet.get("type") != "DISCOVER":
                continue

            peer_id = packet.get("peer_id")
            if not peer_id or peer_id == self.peer_id:
                continue

            enc_public_key_b64 = packet.get("enc_public_key")
            sign_public_key_b64 = packet.get("sign_public_key")
            if not enc_public_key_b64 or not sign_public_key_b64:
                continue

            peer = Peer(
                peer_id=peer_id,
                username=packet.get("username", "unknown"),
                ip=addr[0],
                tcp_port=int(packet.get("port", 0)),
                enc_public_key_b64=enc_public_key_b64,
                sign_public_key_b64=sign_public_key_b64,
                last_seen=time.time(),
            )

            with self._lock:
                self._peers[peer_id] = peer

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            cutoff = time.time() - PEER_STALE_AFTER_SECONDS
            with self._lock:
                stale = [pid for pid, peer in self._peers.items() if peer.last_seen < cutoff]
                for pid in stale:
                    del self._peers[pid]
            time.sleep(1)
