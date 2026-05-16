import argparse
import secrets
import socket
import sys
import threading
import time

from rich.console import Console

from crypto.encrypt import decrypt_message, encrypt_message
from crypto.keys import load_or_create_keys, parse_public_key_b64, parse_verify_key_b64
from crypto.signing import sign_message, verify_signature
from network.discovery import DiscoveryService
from network.transport import TransportService
from ui.terminal import TerminalUI


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostChat (learning scaffold)")
    parser.add_argument("--username", required=True, help="Your display name")
    parser.add_argument("--port", type=int, default=5000, help="TCP listen port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    peer_id = secrets.token_hex(8)
    keys = load_or_create_keys()
    console = Console()
    ui = TerminalUI(username=args.username, fingerprint=keys.fingerprint, port=args.port)
    lock = threading.Lock()

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("", args.port))
    except OSError as exc:
        console.print(f"[red]Cannot start GhostChat on port {args.port}: {exc}[/red]")
        console.print("Try a different --port (example: 5001, 5002, ...).")
        return
    finally:
        probe.close()

    def render_screen() -> None:
        with lock:
            console.clear()
            console.print(ui.header_panel())
            console.print(ui.peers_panel(discovery.peers()))
            console.print(ui.logs_panel())
            console.print("Commands: /peers, /msg <username> <text>, /help, /quit")

    def on_message(packet: dict) -> None:
        if packet.get("type") != "MESSAGE":
            return

        sender = packet.get("sender", "unknown")
        sender_enc_public_b64 = packet.get("sender_enc_public_key")
        sender_sign_public_b64 = packet.get("sender_sign_public_key")
        ciphertext = packet.get("ciphertext")
        signature = packet.get("signature")

        if not all([sender_enc_public_b64, sender_sign_public_b64, ciphertext, signature]):
            ui.add_warn("Dropped malformed encrypted packet")
            render_screen()
            return

        try:
            sender_enc_public = parse_public_key_b64(sender_enc_public_b64)
            plaintext = decrypt_message(keys.enc_private, sender_enc_public, ciphertext)
            sender_verify_key = parse_verify_key_b64(sender_sign_public_b64)
            valid = verify_signature(sender_verify_key, plaintext, signature)
        except Exception as exc:
            ui.add_warn(f"Failed to decrypt/verify: {exc}")
            render_screen()
            return

        if not valid:
            ui.add_warn(f"Signature verification failed for sender {sender}")
            render_screen()
            return

        ui.add_message(sender, plaintext)
        render_screen()

    discovery = DiscoveryService(
        peer_id=peer_id,
        username=args.username,
        tcp_port=args.port,
        enc_public_key_b64=keys.enc_public_b64,
        sign_public_key_b64=keys.sign_public_b64,
    )
    transport = TransportService(listen_port=args.port, on_message=on_message)

    discovery.start()
    transport.start()

    ui.add_info("GhostChat started")
    ui.add_info(f"peer_id={peer_id}")
    ui.add_info("Encryption and signatures enabled")
    render_screen()

    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue

            if line == "/peers":
                peers = discovery.peers()
                ui.add_info(f"{len(peers)} peer(s) discovered")
                render_screen()
                continue

            if line == "/help":
                ui.add_info("/peers: show discovered peers")
                ui.add_info("/msg <username> <text>: send encrypted message")
                ui.add_info("/quit: exit")
                render_screen()
                continue

            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    ui.add_warn("Usage: /msg <username> <text>")
                    render_screen()
                    continue
                target_username, text = parts[1], parts[2]
                peers = discovery.peers()
                target = next((p for p in peers if p.username == target_username), None)
                if not target:
                    ui.add_warn(f"Peer '{target_username}' not found. Try /peers")
                    render_screen()
                    continue
                try:
                    recipient_public = parse_public_key_b64(target.enc_public_key_b64)
                    signature = sign_message(keys.sign_private, text)
                    ciphertext = encrypt_message(keys.enc_private, recipient_public, text)
                    packet = {
                        "type": "MESSAGE",
                        "sender": args.username,
                        "sender_enc_public_key": keys.enc_public_b64,
                        "sender_sign_public_key": keys.sign_public_b64,
                        "ciphertext": ciphertext,
                        "signature": signature,
                    }
                    transport.send_packet(target.ip, target.tcp_port, packet)
                    ui.add_info(f"Encrypted message sent to {target_username}")
                except OSError as exc:
                    ui.add_warn(f"Send failed: {exc}")
                render_screen()
                continue

            if line == "/quit":
                break

            ui.add_warn("Unknown command. Try /help")
            render_screen()

    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        discovery.stop()
        transport.stop()
        console.print("Goodbye.")


if __name__ == "__main__":
    main()
