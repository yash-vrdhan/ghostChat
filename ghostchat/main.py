import argparse
import base64
import os
import secrets
import socket
import tempfile
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console

from ghostchat.crypto.encrypt import decrypt_message, encrypt_message
from ghostchat.crypto.keys import (
    get_key_dir,
    load_or_create_keys,
    parse_public_key_b64,
    parse_verify_key_b64,
)
from ghostchat.crypto.known_hosts import KnownHostsManager
from ghostchat.crypto.signing import sign_message, verify_signature
from ghostchat.media.decoder import MediaDecoder
from ghostchat.media.encoder import MediaEncoder
from ghostchat.network.discovery import DiscoveryService, Peer
from ghostchat.network.gossip import GossipService
from ghostchat.network.transport import TransportService
from ghostchat.protocol.packets import MessagePacket
from ghostchat.session.manager import SessionManager
from ghostchat.ui.banner import get_styled_logo_text
from ghostchat.ui.terminal import TerminalUI


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostChat: P2P Encrypted Terminal Messenger")
    parser.add_argument("--username", required=True, help="Your display name")
    parser.add_argument("--port", type=int, default=5000, help="TCP listen port")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Launch in classic command-line mode instead of the graphical split-pane TUI",
    )
    return parser.parse_args()


class GhostChatApp:
    def __init__(self, username: str, port: int) -> None:
        self.username = username
        self.port = port
        self.peer_id = secrets.token_hex(8)
        self.console = Console()
        self.lock = threading.RLock()

        self.key_dir = get_key_dir(self.username)
        self.keys = load_or_create_keys(profile=self.username)
        self.known_hosts = KnownHostsManager(self.key_dir)
        self.session = SessionManager()
        self.ui = TerminalUI(username=self.username, fingerprint=self.keys.fingerprint, port=self.port)

        self.media_dir = self.key_dir / "media"
        self.media_dir.mkdir(parents=True, exist_ok=True)
        self.encoder = MediaEncoder()
        self.decoder = MediaDecoder(str(self.media_dir))

        self.ui_listeners: Dict[str, List[Callable]] = {
            "peer_change": [],
            "message": [],
            "media": [],
            "group_message": [],
            "channel_change": [],
        }

        self.discovery = DiscoveryService(
            peer_id=self.peer_id,
            username=self.username,
            tcp_port=self.port,
            enc_public_key_b64=self.keys.enc_public_b64,
            sign_public_key_b64=self.keys.sign_public_b64,
            sign_private=self.keys.sign_private,
            known_hosts=self.known_hosts,
            on_peer_change=self._notify_peer_change,
        )
        self.transport = TransportService(
            local_peer_id=self.peer_id,
            listen_port=self.port,
            on_message=self.on_message,
        )
        self.gossip = GossipService(
            local_peer_id=self.peer_id,
            username=self.username,
            sign_public_key_b64=self.keys.sign_public_b64,
            sign_private=self.keys.sign_private,
            transport=self.transport,
            discovery=self.discovery,
            on_group_message=self._on_group_message_received,
            on_channel_change=self._on_channel_change,
        )

    def _on_group_message_received(self, packet: Any, decoded_text: str) -> None:
        routing = self.session.record_incoming_group_message(
            channel=packet.channel,
            sender_username=packet.sender_username,
            text=decoded_text,
            timestamp=packet.timestamp,
        )
        for cb in self.ui_listeners.get("group_message", []):
            try:
                cb(packet.channel, packet.sender_username, decoded_text, routing)
            except Exception:
                pass

    def _on_channel_change(self, channel: str, member_count: int) -> None:
        for cb in self.ui_listeners.get("channel_change", []):
            try:
                cb(channel, member_count)
            except Exception:
                pass

    def send_group_message(self, channel: str, text: str) -> None:
        self.gossip.publish(channel, text)

    def join_channel(self, channel: str, passphrase: Optional[str] = None) -> str:
        canonical = self.session.join_channel(channel)
        if passphrase:
            self.gossip.set_channel_key(canonical, passphrase)
        self.gossip.announce_channel(canonical, "JOIN")
        return canonical

    def leave_channel(self, channel: str) -> bool:
        canonical = channel.lower()
        if not canonical.startswith("#"):
            canonical = f"#{canonical}"
        self.gossip.announce_channel(canonical, "LEAVE")
        return self.session.leave_channel(canonical)

    def register_ui_listener(self, event_type: str, callback: Callable) -> None:
        if event_type in self.ui_listeners:
            self.ui_listeners[event_type].append(callback)

    def _notify_peer_change(self) -> None:
        for cb in self.ui_listeners.get("peer_change", []):
            try:
                cb()
            except Exception:
                pass

    def start_services(self) -> None:
        self.discovery.start()
        self.transport.start()
        self.gossip.announce_channel("#general", "JOIN")

    def stop_services(self) -> None:
        self.discovery.stop()
        self.transport.stop()

    def encoder_renderer_helper(self, filepath: str) -> str:
        return self.decoder.ascii_renderer.get_ascii_from_path(filepath)

    def verify_port_available(self) -> bool:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("", self.port))
            return True
        except OSError as exc:
            self.console.print(f"[red]Cannot start GhostChat on port {self.port}: {exc}[/red]")
            self.console.print("Try a different --port (e.g. 5001, 5002, ...).")
            return False
        finally:
            probe.close()

    def on_message(self, packet: dict) -> None:
        msg_type = packet.get("type")

        if msg_type == "FILE_CHUNK":
            self._handle_file_chunk(packet)
            return

        if msg_type == "GROUP_MESSAGE":
            self.gossip.handle_group_packet(packet)
            return

        if msg_type == "CHANNEL_ANNOUNCE":
            self.gossip.handle_channel_announce(packet)
            return

        if msg_type != "MESSAGE":
            return

        msg = MessagePacket.from_dict(packet)
        if not all([msg.sender_enc_public_key, msg.sender_sign_public_key, msg.ciphertext, msg.signature]):
            with self.lock:
                self.console.print("[yellow]WARN[/yellow] Dropped malformed encrypted packet")
            return

        try:
            sender_enc_public = parse_public_key_b64(msg.sender_enc_public_key)
            plaintext = decrypt_message(self.keys.enc_private, sender_enc_public, msg.ciphertext)
            sender_verify_key = parse_verify_key_b64(msg.sender_sign_public_key)
            valid = verify_signature(sender_verify_key, plaintext, msg.signature)
        except Exception as exc:
            with self.lock:
                self.console.print(f"[yellow]WARN[/yellow] Failed to decrypt/verify: {exc}")
            return

        if not valid:
            with self.lock:
                self.console.print(f"[yellow]WARN[/yellow] Signature verification failed for sender {msg.sender}")
            return

        # TOFU key check
        trusted, warning = self.known_hosts.check_or_pin(
            peer_id=msg.sender_peer_id,
            username=msg.sender,
            enc_public_key=msg.sender_enc_public_key,
            sign_public_key=msg.sender_sign_public_key,
        )
        if not trusted and warning:
            with self.lock:
                self.console.print(f"[red bold]{warning}[/red bold]")

        matched_peer = next((p for p in self.discovery.peers() if p.peer_id == msg.sender_peer_id), None)
        routing = self.session.record_incoming_message(msg.sender_peer_id, matched_peer, plaintext)

        # Notify TUI listeners if active
        listeners = self.ui_listeners.get("message", [])
        if listeners:
            for cb in listeners:
                try:
                    cb(msg.sender, plaintext, msg.sender_peer_id, routing)
                except Exception:
                    pass
            return

        # CLI fallback rendering
        with self.lock:
            if routing["action"] == "active":
                self.console.print(f"[bold cyan][chat:{msg.sender}][/bold cyan] [white]{plaintext}[/white]")
            elif routing["action"] == "auto_opened":
                self.console.print(f"[bold green]{msg.sender}[/bold green] [white]{plaintext}[/white]")
                peer = routing["peer"]
                self.console.print(
                    f"[cyan]INFO[/cyan] Auto-opened chat thread with {peer.username} ({peer.ip}:{peer.tcp_port}). "
                    "Type reply directly or /exit."
                )
            elif routing["action"] == "queued":
                self.console.print(f"[bold green]{msg.sender}[/bold green] [white]{plaintext}[/white]")
                peer = routing["peer"]
                active = routing["active_peer"]
                unread = routing["unread_count"]
                self.console.print(
                    f"[yellow]INFO[/yellow] New message from {peer.username} ({peer.ip}:{peer.tcp_port}) "
                    f"while active chat is {active.username}. unread={unread}. Use '/chat switch' to switch."
                )
            else:
                self.console.print(f"[bold green]{msg.sender}[/bold green] [white]{plaintext}[/white]")

    def _handle_file_chunk(self, packet: dict) -> None:
        sender = packet.get("sender", "unknown")
        sender_peer_id = packet.get("sender_peer_id", "")
        sender_enc_public_b64 = packet.get("sender_enc_public_key")
        sender_sign_public_b64 = packet.get("sender_sign_public_key")
        ciphertext = packet.get("ciphertext")
        signature = packet.get("signature")
        chunk_index = packet.get("chunk_index", 0)
        total_chunks = packet.get("total_chunks", 1)
        filename = packet.get("filename", "unknown")
        media_type = packet.get("media_type", "IMAGE")
        msg_id = packet.get("message_id")

        if not all([sender_enc_public_b64, sender_sign_public_b64, ciphertext, signature]):
            return

        try:
            sender_enc_public = parse_public_key_b64(sender_enc_public_b64)
            chunk_b64 = decrypt_message(self.keys.enc_private, sender_enc_public, ciphertext)
            sender_verify_key = parse_verify_key_b64(sender_sign_public_b64)
            if not verify_signature(sender_verify_key, chunk_b64, signature):
                return
            chunk = base64.b64decode(chunk_b64)
        except Exception:
            return

        complete_file = self.decoder.handle_chunk(
            sender_peer_id, msg_id, chunk_index, total_chunks, chunk, media_type, filename
        )
        if complete_file:
            listeners = self.ui_listeners.get("media", [])
            if listeners:
                for cb in listeners:
                    try:
                        cb(complete_file, media_type, sender)
                    except Exception:
                        pass
            else:
                with self.lock:
                    self.console.print(
                        f"[cyan]INFO[/cyan] Received {media_type} '{filename}' from {sender}. Rendering..."
                    )

                def render() -> None:
                    with self.lock:
                        self.decoder.render_media(complete_file, media_type)

                threading.Thread(target=render, daemon=True).start()

        missing = self.decoder.chunk_manager.get_missing_chunks(sender_peer_id, msg_id)
        if missing and chunk_index == total_chunks - 1:
            request = {
                "type": "RETRANSMIT_REQUEST",
                "sender": self.username,
                "sender_enc_public_key": self.keys.enc_public_b64,
                "sender_sign_public_key": self.keys.sign_public_b64,
                "message_id": msg_id,
                "missing_chunks": missing,
            }
            matched = next((p for p in self.discovery.peers() if p.peer_id == sender_peer_id), None)
            if matched:
                self.transport.send_packet(matched.peer_id, matched.ip, matched.tcp_port, request)

    def send_media(self, target: Peer, filepath: str, media_type: str) -> bool:
        try:
            filename = os.path.basename(filepath)
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
                optimized_path = self.encoder.optimize_image(filepath, tmp.name)

            chunks = self.decoder.chunk_manager.split_file(optimized_path)
            total_chunks = len(chunks)
            message_id = str(uuid.uuid4())
            recipient_public = parse_public_key_b64(target.enc_public_key_b64)

            success = True
            for i, chunk in enumerate(chunks):
                chunk_b64 = base64.b64encode(chunk).decode("utf-8")
                signature = sign_message(self.keys.sign_private, chunk_b64)
                ciphertext = encrypt_message(self.keys.enc_private, recipient_public, chunk_b64)

                packet = {
                    "type": "FILE_CHUNK",
                    "media_type": media_type,
                    "filename": filename,
                    "message_id": message_id,
                    "chunk_index": i,
                    "total_chunks": total_chunks,
                    "sender": self.username,
                    "sender_enc_public_key": self.keys.enc_public_b64,
                    "sender_sign_public_key": self.keys.sign_public_b64,
                    "ciphertext": ciphertext,
                    "signature": signature,
                }
                if not self.transport.send_packet(
                    target.peer_id, target.ip, target.tcp_port, packet, wait_for_ack=True
                ):
                    success = False
                    break

            if optimized_path != filepath:
                try:
                    os.unlink(optimized_path)
                except OSError:
                    pass

            with self.lock:
                if success:
                    self.console.print(f"[cyan]INFO[/cyan] {media_type} '{filename}' sent successfully to {target.username}")
                else:
                    self.console.print(f"[yellow]WARN[/yellow] Failed to send {media_type} to {target.username}")
            return success

        except Exception as e:
            with self.lock:
                self.console.print(f"[red]Error sending media: {e}[/red]")
            return False

    def send_encrypted_message(self, target: Peer, text: str, quiet: bool = False) -> bool:
        try:
            recipient_public = parse_public_key_b64(target.enc_public_key_b64)
            signature = sign_message(self.keys.sign_private, text)
            ciphertext = encrypt_message(self.keys.enc_private, recipient_public, text)

            packet = MessagePacket(
                sender=self.username,
                sender_peer_id=self.peer_id,
                sender_enc_public_key=self.keys.enc_public_b64,
                sender_sign_public_key=self.keys.sign_public_b64,
                ciphertext=ciphertext,
                signature=signature,
                message_id=secrets.token_hex(16),
            )
            success = self.transport.send_packet(
                target.peer_id,
                target.ip,
                target.tcp_port,
                packet.to_dict(),
                wait_for_ack=True,
            )
            if not quiet:
                with self.lock:
                    if success:
                        self.console.print(
                            f"[cyan]INFO[/cyan] Encrypted message sent and ACKed by {target.username} ({target.ip}:{target.tcp_port})"
                        )
                    else:
                        self.console.print(
                            f"[yellow]WARN[/yellow] Message sent to {target.username} but no ACK received."
                        )
            return success
        except OSError as exc:
            if not quiet:
                with self.lock:
                    self.console.print(f"[yellow]WARN[/yellow] Send failed: {exc}")
            return False

    def pick_peer_interactive(self) -> Optional[Peer]:
        peers = self.discovery.peers()
        if not peers:
            with self.lock:
                self.console.print("[yellow]WARN[/yellow] No peers discovered. Try again in a moment.")
            return None

        with self.lock:
            self.console.print("[cyan]Select recipient:[/cyan]")
            for idx, peer in enumerate(peers, start=1):
                trust_indicator = "" if peer.is_trusted else " [red](UNTRUSTED)[/red]"
                self.console.print(f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port}){trust_indicator}")

        selection = input("peer number> ").strip()
        if not selection.isdigit():
            with self.lock:
                self.console.print("[yellow]WARN[/yellow] Invalid selection.")
            return None

        index = int(selection) - 1
        if index < 0 or index >= len(peers):
            with self.lock:
                self.console.print("[yellow]WARN[/yellow] Selection out of range.")
            return None
        return peers[index]

    def start_chat_thread(self, target: Peer) -> None:
        pending_entry = self.session.set_active_peer(target)
        with self.lock:
            self.console.print(
                f"[bold cyan]Chat thread opened with {target.username} ({target.ip}:{target.tcp_port}). "
                "Type messages directly. Use /exit to close thread.[/bold cyan]"
            )
            if pending_entry and pending_entry.get("messages"):
                self.console.print("[cyan]Unread messages:[/cyan]")
                for msg in pending_entry["messages"]:
                    self.console.print(f"[bold cyan][chat:{target.username}][/bold cyan] [white]{msg}[/white]")

    def handle_chat_switch(self, target_token: Optional[str] = None) -> None:
        pending_items = self.session.get_pending_chats()
        if not pending_items:
            with self.lock:
                self.console.print("[cyan]INFO[/cyan] No pending chats to switch.")
            return

        if target_token is None:
            with self.lock:
                self.console.print("[cyan]Select pending chat to switch:[/cyan]")
                for idx, item in enumerate(pending_items, start=1):
                    peer = item["peer"]
                    self.console.print(f"  {idx}. {peer.username} ({peer.ip}:{peer.tcp_port}) unread={item['unread']}")
            selection = input("switch number> ").strip()
            if not selection.isdigit():
                with self.lock:
                    self.console.print("[yellow]WARN[/yellow] Invalid selection.")
                return
            index = int(selection) - 1
            if index < 0 or index >= len(pending_items):
                with self.lock:
                    self.console.print("[yellow]WARN[/yellow] Selection out of range.")
                return
            self.start_chat_thread(pending_items[index]["peer"])
            return

        peers = [item["peer"] for item in pending_items]
        resolved = SessionManager.resolve_target(peers, target_token)
        if resolved is None:
            with self.lock:
                self.console.print(f"[yellow]WARN[/yellow] Pending chat target '{target_token}' not found.")
            return
        if isinstance(resolved, list):
            options = ", ".join(f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved)
            with self.lock:
                self.console.print(f"[yellow]WARN[/yellow] Multiple pending peers for '{target_token}': {options}.")
            return
        self.start_chat_thread(resolved)

    def run_cli(self) -> None:
        if not self.verify_port_available():
            return

        self.start_services()

        try:
            with self.lock:
                self.console.print(get_styled_logo_text())
                self.console.print("[cyan]INFO[/cyan] GhostChat started (v0.2.0 Hardened CLI Mode)")
                self.console.print(f"[cyan]INFO[/cyan] peer_id={self.peer_id}")
                self.console.print(f"[cyan]INFO[/cyan] fingerprint={self.keys.fingerprint}")
                self.console.print("[cyan]INFO[/cyan] Signed discovery, length-prefixed framing & TOFU active")
                self.console.print(self.ui.dashboard(self.discovery.peers()))

            while True:
                line = input("> ").strip()
                if not line:
                    continue

                if line == "/peers":
                    peers = self.discovery.peers()
                    with self.lock:
                        self.console.print(f"[cyan]INFO[/cyan] {len(peers)} peer(s) discovered")
                        self.console.print(self.ui.peers_panel(peers))
                    continue

                if line == "/help":
                    with self.lock:
                        self.console.print("[cyan]INFO[/cyan] /peers: show discovered peers")
                        self.console.print("[cyan]INFO[/cyan] /channels: show subscribed group channels")
                        self.console.print("[cyan]INFO[/cyan] /join <#channel> [passkey]: join or create group channel")
                        self.console.print("[cyan]INFO[/cyan] /leave <#channel>: leave group channel")
                        self.console.print("[cyan]INFO[/cyan] /msg <target> <text>: send message (@user or #channel)")
                        self.console.print("[cyan]INFO[/cyan] /msg: interactive recipient picker")
                        self.console.print("[cyan]INFO[/cyan] /sendimg <target> <path>: send encrypted image")
                        self.console.print("[cyan]INFO[/cyan] /sendgif <target> <path>: send encrypted gif")
                        self.console.print("[cyan]INFO[/cyan] /chat or /chat-thread: open interactive chat thread")
                        self.console.print("[cyan]INFO[/cyan] /chat <target>: open thread directly")
                        self.console.print("[cyan]INFO[/cyan] /chat switch [target]: switch to pending chat")
                        self.console.print("[cyan]INFO[/cyan] /chat pending: list pending chats")
                        self.console.print("[cyan]INFO[/cyan] /exit: close current chat thread")
                        self.console.print("[cyan]INFO[/cyan] /quit: exit GhostChat")
                    continue

                if line == "/channels":
                    channels = self.session.joined_channels
                    with self.lock:
                        self.console.print(f"[cyan]INFO Subscribed channels ({len(channels)}):[/cyan]")
                        for ch in channels:
                            members = self.gossip.get_channel_members_count(ch)
                            self.console.print(f"  • {ch} ({members} online)")
                    continue

                if line.startswith("/join "):
                    parts = line.split(" ", 2)
                    channel_name = parts[1].strip()
                    passphrase = parts[2].strip() if len(parts) > 2 else None
                    canonical = self.join_channel(channel_name, passphrase)
                    with self.lock:
                        self.console.print(f"[green]INFO[/green] Joined channel {canonical}")
                    continue

                if line.startswith("/leave "):
                    target_ch = line.split(" ", 1)[1].strip()
                    if target_ch == "#general":
                        with self.lock:
                            self.console.print("[yellow]WARN[/yellow] Cannot leave #general.")
                        continue
                    success = self.leave_channel(target_ch)
                    with self.lock:
                        if success:
                            self.console.print(f"[cyan]INFO[/cyan] Left channel {target_ch}")
                        else:
                            self.console.print(f"[yellow]WARN[/yellow] Not in {target_ch}")
                    continue

                if line == "/msg":
                    target = self.pick_peer_interactive()
                    if target:
                        text = input("message> ").strip()
                        if text:
                            self.send_encrypted_message(target, text)
                    continue

                if line.startswith("/msg "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        with self.lock:
                            self.console.print("[yellow]WARN[/yellow] Usage: /msg <target> <text>")
                        continue
                    target_token, text = parts[1], parts[2]
                    if target_token.startswith("#"):
                        self.send_group_message(target_token, text)
                        with self.lock:
                            self.console.print(f"[blue][To {target_token}][/blue]: {text}")
                        continue

                    resolved = SessionManager.resolve_target(self.discovery.peers(), target_token)
                    if resolved is None:
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Peer '{target_token}' not found. Try /peers")
                        continue
                    if isinstance(resolved, list):
                        options = ", ".join(f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved)
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Multiple peers named '{target_token}': {options}")
                        continue
                    self.send_encrypted_message(resolved, text)
                    continue

                if line.startswith("/sendimg ") or line.startswith("/sendgif "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        cmd = parts[0]
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Usage: {cmd} <target> <path>")
                        continue
                    cmd, target_token, filepath = parts[0], parts[1], parts[2]
                    media_type = "IMAGE" if cmd == "/sendimg" else "GIF"
                    resolved = SessionManager.resolve_target(self.discovery.peers(), target_token)
                    if resolved is None:
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Peer '{target_token}' not found.")
                        continue
                    if isinstance(resolved, list):
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Multiple peers found for '{target_token}'.")
                        continue
                    if not os.path.exists(filepath):
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] File not found: {filepath}")
                        continue
                    self.send_media(resolved, filepath, media_type)
                    continue

                if line in ("/chat", "/chat-thread"):
                    target = self.pick_peer_interactive()
                    if target:
                        self.start_chat_thread(target)
                    continue

                if line == "/chat pending":
                    pending = self.session.get_pending_chats()
                    with self.lock:
                        if not pending:
                            self.console.print("[cyan]INFO[/cyan] No pending chats.")
                        else:
                            self.console.print("[cyan]Pending chats:[/cyan]")
                            for idx, item in enumerate(pending, start=1):
                                p = item["peer"]
                                self.console.print(f"  {idx}. {p.username} ({p.ip}:{p.tcp_port}) unread={item['unread']}")
                    continue

                if line == "/chat switch":
                    self.handle_chat_switch()
                    continue

                if line.startswith("/chat switch "):
                    target_token = line.split(" ", 2)[2].strip()
                    self.handle_chat_switch(target_token)
                    continue

                if line.startswith("/chat ") or line.startswith("/chat-thread "):
                    target_token = line.split(" ", 1)[1].strip()
                    resolved = SessionManager.resolve_target(self.discovery.peers(), target_token)
                    if resolved is None:
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Peer '{target_token}' not found.")
                        continue
                    if isinstance(resolved, list):
                        options = ", ".join(f"{p.username}@{p.tcp_port} ({p.ip}:{p.tcp_port})" for p in resolved)
                        with self.lock:
                            self.console.print(f"[yellow]WARN[/yellow] Multiple peers named '{target_token}': {options}")
                        continue
                    self.start_chat_thread(resolved)
                    continue

                # Thread active mode handling
                if self.session.chat_peer is not None:
                    if line == "/exit":
                        with self.lock:
                            self.console.print("[cyan]INFO[/cyan] Chat thread closed.")
                        self.session.close_active_thread()
                        continue

                    if line.startswith("/sendimg ") or line.startswith("/sendgif "):
                        parts = line.split(" ", 1)
                        if len(parts) < 2:
                            cmd = parts[0]
                            with self.lock:
                                self.console.print(f"[yellow]WARN[/yellow] Usage: {cmd} <path>")
                            continue
                        cmd, filepath = parts[0], parts[1].strip()
                        media_type = "IMAGE" if cmd == "/sendimg" else "GIF"
                        if not os.path.exists(filepath):
                            with self.lock:
                                self.console.print(f"[yellow]WARN[/yellow] File not found: {filepath}")
                            continue
                        self.send_media(self.session.chat_peer, filepath, media_type)
                        continue

                    if line.startswith("/"):
                        with self.lock:
                            self.console.print("[yellow]WARN[/yellow] Unknown chat command. Use /exit to close thread.")
                        continue

                    target = self.session.chat_peer
                    success = self.send_encrypted_message(target, line)
                    if not success:
                        with self.lock:
                            self.console.print(
                                "[yellow]WARN[/yellow] Message delivery failed (peer offline or ACK timeout)."
                            )
                    continue

                if line == "/quit":
                    break

                with self.lock:
                    self.console.print("[yellow]WARN[/yellow] Unknown command. Try /help")

        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self.stop_services()
            self.console.print("Goodbye.")


def main() -> None:
    args = parse_args()
    app = GhostChatApp(username=args.username, port=args.port)
    if args.cli:
        app.run_cli()
    else:
        from ghostchat.ui.app import GhostChatTUIApp

        tui = GhostChatTUIApp(backend=app)
        tui.run()


if __name__ == "__main__":
    main()
