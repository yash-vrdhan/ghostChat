import json
import socket
import threading
import uuid
from typing import Callable, Dict, Set, Optional, Tuple


MessageHandler = Callable[[dict], None]


class TransportService:
    def __init__(self, local_peer_id: str, listen_port: int, on_message: MessageHandler) -> None:
        self.local_peer_id = local_peer_id
        self.listen_port = listen_port
        self.on_message = on_message
        self._stop_event = threading.Event()

        # peer_id -> socket
        self.peers: Dict[str, socket.socket] = {}
        # peer_id -> Lock (per-peer write lock)
        self.write_locks: Dict[str, threading.Lock] = {}
        self.peers_lock = threading.Lock()

        # (peer_id, message_id) -> Event (set when ACK received)
        self.pending_acks: Dict[Tuple[str, str], threading.Event] = {}
        self.acks_lock = threading.Lock()

        # Recently processed message IDs to prevent duplicates
        self.processed_msgs: Set[str] = set()
        self.processed_msgs_lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()
        with self.peers_lock:
            for sock in list(self.peers.values()):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except OSError:
                    pass
            self.peers.clear()
            self.write_locks.clear()

    def _get_connection(self, peer_id: str, ip: str, port: int) -> Tuple[Optional[socket.socket], Optional[threading.Lock]]:
        with self.peers_lock:
            if peer_id in self.peers:
                return self.peers[peer_id], self.write_locks[peer_id]

        try:
            sock = socket.create_connection((ip, port), timeout=3)
            with self.peers_lock:
                if peer_id in self.peers:
                    sock.close()
                    return self.peers[peer_id], self.write_locks[peer_id]
                self.peers[peer_id] = sock
                lock = threading.Lock()
                self.write_locks[peer_id] = lock

            threading.Thread(target=self._handle_conn, args=(sock, peer_id), daemon=True).start()
            return sock, lock
        except OSError:
            return None, None

    def send_packet(self, peer_id: str, ip: str, port: int, packet: dict, wait_for_ack: bool = False) -> bool:
        if "message_id" not in packet:
            packet["message_id"] = str(uuid.uuid4())
        packet["sender_peer_id"] = self.local_peer_id

        msg_id = packet["message_id"]
        ack_event = None
        if wait_for_ack:
            ack_event = threading.Event()
            with self.acks_lock:
                self.pending_acks[(peer_id, msg_id)] = ack_event

        sock, write_lock = self._get_connection(peer_id, ip, port)
        if not sock or not write_lock:
            if ack_event:
                with self.acks_lock:
                    self.pending_acks.pop((peer_id, msg_id), None)
            return False

        data = json.dumps(packet).encode("utf-8") + b"\n"
        try:
            with write_lock:
                sock.sendall(data)
        except OSError:
            self._remove_peer(peer_id, sock)
            if ack_event:
                with self.acks_lock:
                    self.pending_acks.pop((peer_id, msg_id), None)
            return False

        if wait_for_ack and ack_event:
            success = ack_event.wait(timeout=5.0)
            with self.acks_lock:
                self.pending_acks.pop((peer_id, msg_id), None)
            return success

        return True

    def _remove_peer(self, peer_id: str, sock: socket.socket) -> None:
        with self.peers_lock:
            if self.peers.get(peer_id) == sock:
                del self.peers[peer_id]
                del self.write_locks[peer_id]
        try:
            sock.close()
        except OSError:
            pass

    def _listen_loop(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("", self.listen_port))
        except OSError:
            return
        server.listen()

        while not self._stop_event.is_set():
            try:
                server.settimeout(1.0)
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, identified_peer_id: Optional[str] = None) -> None:
        peer_id = identified_peer_id
        local_write_lock: Optional[threading.Lock] = None
        if identified_peer_id is not None:
            with self.peers_lock:
                local_write_lock = self.write_locks.get(identified_peer_id)
        try:
            f = conn.makefile("rb")
            while not self._stop_event.is_set():
                line = f.readline()
                if not line:
                    break
                try:
                    packet = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue

                sender_peer_id = packet.get("sender_peer_id")
                if sender_peer_id:
                    if peer_id is None:
                        peer_id = sender_peer_id
                        with self.peers_lock:
                            if peer_id in self.peers:
                                # Keep canonical mapping stable and use a local lock for this connection.
                                local_write_lock = self.write_locks[peer_id]
                            else:
                                self.peers[peer_id] = conn
                                local_write_lock = threading.Lock()
                                self.write_locks[peer_id] = local_write_lock
                    elif peer_id != sender_peer_id:
                        # Malicious/buggy peer claiming different peer_id
                        # Ignore this packet and possibly close connection
                        continue

                msg_type = packet.get("type")
                msg_id = packet.get("message_id")

                if msg_type == "ACK":
                    if msg_id and peer_id:
                        with self.acks_lock:
                            key = (peer_id, msg_id)
                            if key in self.pending_acks:
                                self.pending_acks[key].set()
                    continue

                if msg_id:
                    is_duplicate = False
                    with self.processed_msgs_lock:
                        if msg_id in self.processed_msgs:
                            is_duplicate = True
                        else:
                            self.processed_msgs.add(msg_id)
                            if len(self.processed_msgs) > 1000:
                                self.processed_msgs.remove(next(iter(self.processed_msgs)))

                    if peer_id:
                        self._send_ack(peer_id, msg_id, conn=conn, write_lock=local_write_lock)

                    if is_duplicate:
                        continue

                self.on_message(packet)
        except OSError:
            pass
        finally:
            if peer_id:
                with self.peers_lock:
                    if self.peers.get(peer_id) == conn:
                        del self.peers[peer_id]
                        del self.write_locks[peer_id]
            conn.close()

    def _send_ack(
        self,
        peer_id: str,
        message_id: str,
        conn: Optional[socket.socket] = None,
        write_lock: Optional[threading.Lock] = None,
    ) -> None:
        if conn is None or write_lock is None:
            with self.peers_lock:
                conn = self.peers.get(peer_id)
                write_lock = self.write_locks.get(peer_id)

        if not conn or not write_lock:
            return

        ack = {
            "type": "ACK",
            "message_id": message_id,
            "sender_peer_id": self.local_peer_id
        }
        try:
            data = json.dumps(ack).encode("utf-8") + b"\n"
            with write_lock:
                conn.sendall(data)
        except OSError:
            pass
