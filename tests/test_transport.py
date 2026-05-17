import socket
import threading
import time

import pytest

from ghostchat.network.transport import TransportService


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", 0))
        except PermissionError:
            pytest.skip("Socket bind is not permitted in this execution environment.")
        return int(s.getsockname()[1])


def _wait_until(predicate, timeout: float = 2.0, interval: float = 0.02) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_send_packet_waits_for_ack_and_delivers_once() -> None:
    recv_packets: list[dict] = []

    def on_message(packet: dict) -> None:
        recv_packets.append(packet)

    port_a = _free_port()
    port_b = _free_port()

    node_a = TransportService(local_peer_id="peer-a", listen_port=port_a, on_message=lambda _: None)
    node_b = TransportService(local_peer_id="peer-b", listen_port=port_b, on_message=on_message)

    node_a.start()
    node_b.start()

    try:
        packet = {"type": "MESSAGE", "payload": "hello"}
        ok = node_a.send_packet("peer-b", "127.0.0.1", port_b, packet, wait_for_ack=True)

        assert ok is True
        assert _wait_until(lambda: len(recv_packets) == 1)
        assert recv_packets[0]["payload"] == "hello"
        assert recv_packets[0]["sender_peer_id"] == "peer-a"
        assert "message_id" in recv_packets[0]
    finally:
        node_a.stop()
        node_b.stop()


def test_duplicate_message_id_is_acked_but_not_redelivered() -> None:
    recv_packets: list[dict] = []

    def on_message(packet: dict) -> None:
        recv_packets.append(packet)

    port_a = _free_port()
    port_b = _free_port()

    node_a = TransportService(local_peer_id="peer-a", listen_port=port_a, on_message=lambda _: None)
    node_b = TransportService(local_peer_id="peer-b", listen_port=port_b, on_message=on_message)

    node_a.start()
    node_b.start()

    try:
        msg_id = "fixed-id-1"
        first = {"type": "MESSAGE", "payload": "hello", "message_id": msg_id}
        second = {"type": "MESSAGE", "payload": "hello", "message_id": msg_id}

        assert node_a.send_packet("peer-b", "127.0.0.1", port_b, first, wait_for_ack=True) is True
        assert node_a.send_packet("peer-b", "127.0.0.1", port_b, second, wait_for_ack=True) is True

        assert _wait_until(lambda: len(recv_packets) == 1)
        assert recv_packets[0]["message_id"] == msg_id
    finally:
        node_a.stop()
        node_b.stop()


def test_connection_reused_for_multiple_messages() -> None:
    recv_count = 0
    recv_lock = threading.Lock()

    def on_message(_: dict) -> None:
        nonlocal recv_count
        with recv_lock:
            recv_count += 1

    port_a = _free_port()
    port_b = _free_port()

    node_a = TransportService(local_peer_id="peer-a", listen_port=port_a, on_message=lambda _: None)
    node_b = TransportService(local_peer_id="peer-b", listen_port=port_b, on_message=on_message)

    node_a.start()
    node_b.start()

    try:
        assert node_a.send_packet("peer-b", "127.0.0.1", port_b, {"type": "MESSAGE", "n": 1}, wait_for_ack=True)
        assert node_a.send_packet("peer-b", "127.0.0.1", port_b, {"type": "MESSAGE", "n": 2}, wait_for_ack=True)

        assert _wait_until(lambda: recv_count == 2)
        with node_a.peers_lock:
            assert "peer-b" in node_a.peers
            assert "peer-b" in node_a.write_locks
    finally:
        node_a.stop()
        node_b.stop()


def test_send_packet_returns_false_for_unreachable_peer() -> None:
    port_a = _free_port()
    node_a = TransportService(local_peer_id="peer-a", listen_port=port_a, on_message=lambda _: None)
    node_a.start()

    try:
        # Intentionally use a high, unbound local port.
        ok = node_a.send_packet("peer-z", "127.0.0.1", 65500, {"type": "MESSAGE"}, wait_for_ack=True)
        assert ok is False
    finally:
        node_a.stop()
