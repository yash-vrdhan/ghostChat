import argparse
import secrets
import socket
import threading

from rich.console import Console

from ghostchat.crypto.encrypt import decrypt_message, encrypt_message
from ghostchat.crypto.keys import (
    load_or_create_keys,
    parse_public_key_b64,
    parse_verify_key_b64,
)
from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.network.discovery import DiscoveryService
from ghostchat.network.transport import TransportService
from ghostchat.ui.terminal import TerminalUI


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostChat (learning scaffold)")
    parser.add_argument("--username", required=True, help="Your display name")
    parser.add_argument("--port", type=int, default=5000, help="TCP listen port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    peer_id = secrets.token_hex(8)
    keys = load_or_create_keys(profile=args.username)
    console = Console()
    ui = TerminalUI(username=args.username, fingerprint=keys.fingerprint, port=args.port)
    lock = threading.RLock()
    state = {"chat_peer": None, "pending_chats": {}}

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

    def render_dashboard() -> None:
        with lock:
            console.print(ui.dashboard(discovery.peers()))

    def on_message(packet: dict) -> None:
        if packet.get("type") != "MESSAGE":
            return

        sender = packet.get("sender", "unknown")
        sender_peer_id = packet.get("sender_peer_id")
        sender_enc_public_b64 = packet.get("sender_enc_public_key")
        sender_sign_public_b64 = packet.get("sender_sign_public_key")
        ciphertext = packet.get("ciphertext")
        signature = packet.get("signature")

        if not all([sender_enc_public_b64, sender_sign_public_b64, ciphertext, signature]):
            with lock:
                console.print("[yellow]WARN[/yellow] Dropped malformed encrypted packet")
            return

        try:
            sender_enc_public = parse_public_key_b64(sender_enc_public_b64)
            plaintext = decrypt_message(keys.enc_private, sender_enc_public, ciphertext)
            sender_verify_key = parse_verify_key_b64(sender_sign_public_b64)
            valid = verify_signature(sender_verify_key, plaintext, signature)
        except Exception as exc:
            with lock:
                console.print(f"[yellow]WARN[/yellow] Failed to decrypt/verify: {exc}")
            return

        if not valid:
            with lock:
                console.print(
                    f"[yellow]WARN[/yellow] Signature verification failed for sender {sender}"
                )
            return

        with lock:
            chat_peer = state["chat_peer"]
            if chat_peer and sender_peer_id == chat_peer.peer_id:
                console.print(
                    f"[bold cyan][chat:{sender}][/bold cyan] [white]{plaintext}[/white]"
                )
            else:
                console.print(f"[bold green]{sender}[/bold green] [white]{plaintext}[/white]")
                if sender_peer_id:
                    matched = next((p for p in discovery.peers() if p.peer_id == sender_peer_id), None)
                    if matched is not None:
                        if chat_peer is None:
                            state["chat_peer"] = matched
                            console.print(
                                f"[cyan]INFO[/cyan] Auto-opened chat thread with {matched.username} "
                                f"({matched.ip}:{matched.tcp_port}). Type reply directly or /exit."
                            )
                        elif chat_peer.peer_id != sender_peer_id:
                            pending = state["pending_chats"]
                            if sender_peer_id in pending:
                                pending[sender_peer_id]["unread"] += 1
                                pending[sender_peer_id]["peer"] = matched
                                pending[sender_peer_id]["messages"].append(plaintext)
                            else:
                                pending[sender_peer_id] = {
                                    "peer": matched,
                                    "unread": 1,
                                    "messages": [plaintext],
                                }
                            unread = pending[sender_peer_id]["unread"]
                            console.print(
                                f"[yellow]INFO[/yellow] New message from {matched.username} "
                                f"({matched.ip}:{matched.tcp_port}) while active chat is "
                                f"{chat_peer.username}. unread={unread}. Use '/chat switch' to switch."
                            )

    def resolve_target(peers: list, target_token: str):
        # Explicit routing for duplicates: allow `username@port` or `ip:port`.
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
        return matches

    def interactive_send_message() -> None:
        peers = discovery.peers()
        if not peers:
            with lock:
                console.print("[yellow]WARN[/yellow] No peers discovered. Try again in a moment.")
            return

        with lock:
            console.print("[cyan]Select recipient:[/cyan]")
            for idx, peer in enumerate(peers, start=1):
                console.print(f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port})")

        selection = input("peer number> ").strip()
        if not selection.isdigit():
            with lock:
                console.print("[yellow]WARN[/yellow] Invalid selection.")
            return

        index = int(selection) - 1
        if index < 0 or index >= len(peers):
            with lock:
                console.print("[yellow]WARN[/yellow] Selection out of range.")
            return

        text = input("message> ").strip()
        if not text:
            with lock:
                console.print("[yellow]WARN[/yellow] Message is empty.")
            return

        target = peers[index]
        send_encrypted_message(target, text)

    def pick_peer_interactive():
        peers = discovery.peers()
        if not peers:
            with lock:
                console.print("[yellow]WARN[/yellow] No peers discovered. Try again in a moment.")
            return None

        with lock:
            console.print("[cyan]Select recipient:[/cyan]")
            for idx, peer in enumerate(peers, start=1):
                console.print(f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port})")

        selection = input("peer number> ").strip()
        if not selection.isdigit():
            with lock:
                console.print("[yellow]WARN[/yellow] Invalid selection.")
            return None

        index = int(selection) - 1
        if index < 0 or index >= len(peers):
            with lock:
                console.print("[yellow]WARN[/yellow] Selection out of range.")
            return None
        return peers[index]

    def send_encrypted_message(target, text: str) -> bool:
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
            success = transport.send_packet(
                target.peer_id,
                target.ip,
                target.tcp_port,
                packet,
                wait_for_ack=True,
            )
            with lock:
                if success:
                    console.print(
                        f"[cyan]INFO[/cyan] Encrypted message sent and ACKed by {target.username} ({target.ip}:{target.tcp_port})"
                    )
                else:
                    console.print(
                        f"[yellow]WARN[/yellow] Message sent to {target.username} but no ACK received."
                    )
            return success
        except OSError as exc:
            with lock:
                console.print(f"[yellow]WARN[/yellow] Send failed: {exc}")
            return False

    def start_chat_thread(target) -> None:
        pending_entry = state["pending_chats"].pop(target.peer_id, None)
        state["chat_peer"] = target
        with lock:
            console.print(
                f"[bold cyan]Chat thread opened with {target.username} ({target.ip}:{target.tcp_port}). "
                "Type messages directly. Use /exit to close thread.[/bold cyan]"
            )
            if pending_entry and pending_entry.get("messages"):
                console.print("[cyan]Unread messages:[/cyan]")
                for msg in pending_entry["messages"]:
                    console.print(
                        f"[bold cyan][chat:{target.username}][/bold cyan] [white]{msg}[/white]"
                    )

    def show_pending_chats() -> None:
        pending = state["pending_chats"]
        if not pending:
            with lock:
                console.print("[cyan]INFO[/cyan] No pending chats.")
            return
        with lock:
            console.print("[cyan]Pending chats:[/cyan]")
            for idx, item in enumerate(pending.values(), start=1):
                peer = item["peer"]
                unread = item["unread"]
                console.print(
                    f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port}) unread={unread}"
                )

    def switch_chat_thread(target_token: str | None = None) -> None:
        pending = state["pending_chats"]
        if not pending:
            with lock:
                console.print("[cyan]INFO[/cyan] No pending chats to switch.")
            return

        if target_token is None:
            with lock:
                console.print("[cyan]Select pending chat to switch:[/cyan]")
                items = list(pending.values())
                for idx, item in enumerate(items, start=1):
                    peer = item["peer"]
                    console.print(
                        f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port}) unread={item['unread']}"
                    )
            selection = input("switch number> ").strip()
            if not selection.isdigit():
                with lock:
                    console.print("[yellow]WARN[/yellow] Invalid selection.")
                return
            index = int(selection) - 1
            if index < 0 or index >= len(items):
                with lock:
                    console.print("[yellow]WARN[/yellow] Selection out of range.")
                return
            start_chat_thread(items[index]["peer"])
            return

        peers = [item["peer"] for item in pending.values()]
        resolved = resolve_target(peers, target_token)
        if resolved is None:
            with lock:
                console.print(
                    f"[yellow]WARN[/yellow] Pending chat target '{target_token}' not found."
                )
            return
        if isinstance(resolved, list):
            options = ", ".join(f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved)
            with lock:
                console.print(
                    f"[yellow]WARN[/yellow] Multiple pending peers for '{target_token}': {options}. "
                    "Use '/chat switch' interactive picker."
                )
            return
        start_chat_thread(resolved)

    discovery = DiscoveryService(
        peer_id=peer_id,
        username=args.username,
        tcp_port=args.port,
        enc_public_key_b64=keys.enc_public_b64,
        sign_public_key_b64=keys.sign_public_b64,
    )
    transport = TransportService(local_peer_id=peer_id, listen_port=args.port, on_message=on_message)

    discovery.start()
    transport.start()

    try:
        with lock:
            console.print("[cyan]INFO[/cyan] GhostChat started")
            console.print(f"[cyan]INFO[/cyan] peer_id={peer_id}")
            console.print("[cyan]INFO[/cyan] Encryption and signatures enabled")
            render_dashboard()

        while True:
            line = input("> ").strip()
            if not line:
                continue

            if line == "/peers":
                peers = discovery.peers()
                with lock:
                    console.print(f"[cyan]INFO[/cyan] {len(peers)} peer(s) discovered")
                    console.print(ui.peers_panel(peers))
                    duplicate_usernames = {
                        p.username for p in peers if sum(1 for q in peers if q.username == p.username) > 1
                    }
                    if duplicate_usernames:
                        console.print(
                            "[yellow]WARN[/yellow] Duplicate usernames detected. "
                            "Use '/msg <username>@<port> <text>' to target a specific peer."
                        )
                continue

            if line == "/help":
                with lock:
                    console.print("[cyan]INFO[/cyan] /peers: show discovered peers")
                    console.print("[cyan]INFO[/cyan] /msg <username> <text>: send encrypted message")
                    console.print("[cyan]INFO[/cyan] /msg: interactive recipient picker")
                    console.print("[cyan]INFO[/cyan] /chat or /chat-thread: open interactive chat thread")
                    console.print("[cyan]INFO[/cyan] /chat <target>: open thread to username / username@port / ip:port")
                    console.print("[cyan]INFO[/cyan] /chat switch [target]: switch to pending chat")
                    console.print("[cyan]INFO[/cyan] /chat pending: list pending chats")
                    console.print("[cyan]INFO[/cyan] /exit: close current chat thread")
                    console.print("[cyan]INFO[/cyan] /quit: exit")
                continue

            if line == "/msg":
                interactive_send_message()
                continue

            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    with lock:
                        console.print("[yellow]WARN[/yellow] Usage: /msg <username> <text>")
                    continue
                target_username, text = parts[1], parts[2]
                peers = discovery.peers()
                resolved = resolve_target(peers, target_username)
                if resolved is None:
                    with lock:
                        console.print(
                            f"[yellow]WARN[/yellow] Peer '{target_username}' not found. Try /peers"
                        )
                    continue
                if isinstance(resolved, list):
                    options = ", ".join(
                        f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved
                    )
                    with lock:
                        console.print(
                            f"[yellow]WARN[/yellow] Multiple peers named '{target_username}': {options}. "
                            "Use '/msg <username>@<port> <text>' or use the interactive picker by typing '/msg'."
                        )
                    continue
                target = resolved
                send_encrypted_message(target, text)
                continue

            if line == "/chat" or line == "/chat-thread":
                target = pick_peer_interactive()
                if target:
                    start_chat_thread(target)
                continue

            if line == "/chat pending":
                show_pending_chats()
                continue

            if line == "/chat switch":
                switch_chat_thread()
                continue

            if line.startswith("/chat switch "):
                target_token = line.split(" ", 2)[2].strip()
                if not target_token:
                    with lock:
                        console.print("[yellow]WARN[/yellow] Usage: /chat switch [target]")
                    continue
                switch_chat_thread(target_token)
                continue

            if line.startswith("/chat ") or line.startswith("/chat-thread "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    with lock:
                        console.print("[yellow]WARN[/yellow] Usage: /chat <target>")
                    continue
                target_token = parts[1].strip()
                peers = discovery.peers()
                resolved = resolve_target(peers, target_token)
                if resolved is None:
                    with lock:
                        console.print(
                            f"[yellow]WARN[/yellow] Peer '{target_token}' not found. Try /peers"
                        )
                    continue
                if isinstance(resolved, list):
                    options = ", ".join(
                        f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved
                    )
                    with lock:
                        console.print(
                            f"[yellow]WARN[/yellow] Multiple peers named '{target_token}': {options}. "
                            "Use '/chat <username>@<port>' or '/chat' picker."
                        )
                    continue
                start_chat_thread(resolved)
                continue

            if state["chat_peer"] is not None:
                if line == "/exit":
                    with lock:
                        console.print("[cyan]INFO[/cyan] Chat thread closed.")
                    state["chat_peer"] = None
                    continue
                if line.startswith("/"):
                    with lock:
                        console.print("[yellow]WARN[/yellow] Unknown chat command. Use /exit to close chat.")
                    continue
                target = state["chat_peer"]
                success = send_encrypted_message(target, line)
                if not success:
                    with lock:
                        console.print(
                            "[yellow]WARN[/yellow] Chat thread closed because peer is offline or ACK failed."
                        )
                    state["chat_peer"] = None
                continue

            if line == "/quit":
                break

            with lock:
                console.print("[yellow]WARN[/yellow] Unknown command. Try /help")

    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        discovery.stop()
        transport.stop()
        console.print("Goodbye.")


if __name__ == "__main__":
    main()
