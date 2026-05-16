import json
import socket
import threading
from typing import Callable


MessageHandler = Callable[[dict], None]


class TransportService:
    def __init__(self, listen_port: int, on_message: MessageHandler) -> None:
        self.listen_port = listen_port
        self.on_message = on_message
        self._stop_event = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()

    def send_packet(self, ip: str, port: int, packet: dict) -> None:
        data = json.dumps(packet).encode("utf-8") + b"\n"
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.sendall(data)

    def _listen_loop(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", self.listen_port))
        server.listen()

        while not self._stop_event.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue

            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            file = conn.makefile("rb")
            line = file.readline()
            if not line:
                return
            try:
                packet = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return
            self.on_message(packet)
