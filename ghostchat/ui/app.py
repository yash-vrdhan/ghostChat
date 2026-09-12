import os
import threading
import time
from typing import Any, Dict, List, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from ghostchat.network.discovery import Peer
from ghostchat.session.manager import SessionManager
from ghostchat.ui.banner import (
    MINI_LOGO,
    get_welcome_dashboard_renderable,
)


class PeerItem(ListItem):
    """List item representing a discovered peer in the sidebar."""

    def __init__(self, peer: Peer, unread_count: int = 0) -> None:
        super().__init__()
        self.peer = peer
        self.unread_count = unread_count

    def compose(self) -> ComposeResult:
        status_dot = "[bold green]●[/bold green]" if self.peer.is_trusted else "[bold red]▲[/bold red]"
        unread_badge = f" [bold yellow][{self.unread_count}][/bold yellow]" if self.unread_count > 0 else ""
        yield Label(f"{status_dot} @{self.peer.username} [dim]({self.peer.tcp_port})[/dim]{unread_badge}")


class GhostChatTUIApp(App):
    """Full graphical Terminal User Interface for GhostChat."""

    TITLE = "GhostChat"
    SUB_TITLE = "LAN-first End-to-End Encrypted P2P Messenger"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+p", "focus_peers", "Peers", show=True),
        Binding("ctrl+l", "clear_chat", "Clear", show=True),
        Binding("escape", "close_thread", "Exit Thread", show=True),
    ]

    CSS = """
    Screen {
        background: #11111b;
        color: #cdd6f4;
    }

    Header {
        background: #181825;
        color: #89b4fa;
        dock: top;
        height: 1;
    }

    Footer {
        background: #181825;
        color: #6c7086;
        dock: bottom;
        height: 1;
    }

    #main-container {
        height: 1fr;
        width: 100%;
    }

    #sidebar {
        width: 32;
        dock: left;
        border-right: vkey #313244;
        background: #181825;
        padding: 0 1;
    }

    #sidebar-header {
        height: 3;
        border-bottom: solid #313244;
        content-align: left middle;
        color: #89b4fa;
        text-style: bold;
    }

    #peer-list {
        height: 1fr;
        background: transparent;
        border: none;
        padding-top: 1;
    }

    #peer-list:focus {
        border: none;
    }

    #system-info {
        height: auto;
        border-top: solid #313244;
        padding: 1 0;
        color: #6c7086;
    }

    #content-area {
        height: 1fr;
        width: 1fr;
        background: #11111b;
    }

    #chat-header {
        height: 3;
        background: #181825;
        border-bottom: solid #313244;
        padding: 0 1;
        content-align: left middle;
        color: #00f0ff;
        text-style: bold;
    }

    #welcome-container {
        height: 1fr;
        padding: 1 2;
        overflow-y: auto;
    }

    #chat-log {
        height: 1fr;
        background: #11111b;
        padding: 0 1;
        border: none;
        display: none;
    }

    #input-dock {
        height: 3;
        dock: bottom;
        background: #181825;
        border-top: solid #313244;
        padding: 0 1;
    }

    #message-input {
        background: #1e1e2e;
        border: tall #313244;
        color: #cdd6f4;
    }

    #message-input:focus {
        border: tall #00f0ff;
    }
    """

    def __init__(self, backend: Any) -> None:
        super().__init__()
        self.backend = backend
        self.active_peer: Optional[Peer] = None
        self._refresh_timer = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                yield Static(f"{MINI_LOGO}\n[dim]Peers on LAN[/dim]", id="sidebar-header")
                yield ListView(id="peer-list")
                yield Static(
                    f"[dim]Node:[/dim] [cyan]@{self.backend.username}[/cyan]\n"
                    f"[dim]Port:[/dim] [green]{self.backend.port}[/green] [dim]• TOFU Active[/dim]",
                    id="system-info",
                )

            with Vertical(id="content-area"):
                yield Static(
                    "👻 GhostChat • No active thread (Select a peer on the left or type /help)",
                    id="chat-header",
                )
                with Container(id="welcome-container"):
                    yield Static(
                        get_welcome_dashboard_renderable(
                            self.backend.username,
                            self.backend.port,
                            self.backend.keys.fingerprint,
                        )
                    )
                yield RichLog(id="chat-log", markup=True, wrap=True, highlight=False)

        with Horizontal(id="input-dock"):
            yield Input(
                placeholder="Type a message or /command... (Esc to unselect, /help for manual)",
                id="message-input",
            )
        yield Footer()

    def on_mount(self) -> None:
        # Connect backend thread-safe listeners
        self.backend.register_ui_listener("peer_change", self._on_peer_change_callback)
        self.backend.register_ui_listener("message", self._on_message_callback)
        self.backend.register_ui_listener("media", self._on_media_callback)

        # Start backend services if not already started
        self.backend.start_services()

        # Initial sidebar render and periodic refresh (every 2s)
        self.refresh_peer_sidebar()
        self.set_interval(2.0, self.refresh_peer_sidebar)

        self.query_one("#message-input", Input).focus()

    def refresh_peer_sidebar(self) -> None:
        peers = self.backend.discovery.peers()
        peer_list = self.query_one("#peer-list", ListView)
        peer_list.clear()

        pending_chats = self.backend.session.get_pending_chats()
        unread_map = {item["peer"].peer_id: item["unread"] for item in pending_chats}

        if not peers:
            peer_list.append(ListItem(Label("[dim italic]No peers discovered[/dim italic]")))
            return

        for p in peers:
            unread = unread_map.get(p.peer_id, 0)
            peer_list.append(PeerItem(peer=p, unread_count=unread))

    def _on_peer_change_callback(self) -> None:
        self.call_from_thread(self.refresh_peer_sidebar)

    def _on_message_callback(self, sender: str, text: str, sender_peer_id: str, routing: dict) -> None:
        def update_ui() -> None:
            chat_log = self.query_one("#chat-log", RichLog)
            timestamp = time.strftime("%H:%M:%S")

            if routing.get("action") == "active":
                chat_log.write(f"[{timestamp}] [bold cyan][@{sender}]:[/bold cyan] [white]{text}[/white]")
            elif routing.get("action") == "auto_opened":
                # Auto-open thread
                matched = routing.get("peer")
                if matched:
                    self.open_chat_thread(matched, quiet=True)
                chat_log.write(f"[{timestamp}] [bold cyan][@{sender}]:[/bold cyan] [white]{text}[/white]")
            elif routing.get("action") == "queued":
                # Background unread
                self.refresh_peer_sidebar()
                if self.active_peer:
                    chat_log.write(
                        f"[dim][{timestamp}] [yellow]Notice:[/yellow] New message from @{sender}. "
                        "Switch peer to view.[/dim]"
                    )
            else:
                chat_log.write(f"[{timestamp}] [bold green][@{sender}]:[/bold green] [white]{text}[/white]")

        self.call_from_thread(update_ui)

    def _on_media_callback(self, filepath: str, media_type: str, sender: str) -> None:
        def update_ui() -> None:
            chat_log = self.query_one("#chat-log", RichLog)
            timestamp = time.strftime("%H:%M:%S")
            chat_log.write(f"[{timestamp}] [bold magenta]Received {media_type} from @{sender}:[/bold magenta]")
            try:
                ascii_text = self.backend.encoder_renderer_helper(filepath)
                chat_log.write(Text(ascii_text, style="cyan"))
            except Exception as exc:
                chat_log.write(f"[red]Failed to render media: {exc}[/red]")

        self.call_from_thread(update_ui)

    def open_chat_thread(self, peer: Peer, quiet: bool = False) -> None:
        self.active_peer = peer
        pending_entry = self.backend.session.set_active_peer(peer)

        welcome_view = self.query_one("#welcome-container")
        chat_log = self.query_one("#chat-log", RichLog)
        chat_header = self.query_one("#chat-header", Static)
        message_input = self.query_one("#message-input", Input)

        welcome_view.styles.display = "none"
        chat_log.styles.display = "block"

        trust_tag = "[green]● TOFU Verified[/green]" if peer.is_trusted else "[red]▲ UNTRUSTED[/red]"
        chat_header.update(
            f"💬 Chatting with [bold white]@{peer.username}[/bold white] "
            f"([dim]{peer.ip}:{peer.tcp_port}[/dim]) • {trust_tag}"
        )
        message_input.placeholder = f"Message @{peer.username}... (Press Esc to close thread)"
        message_input.focus()

        if not quiet:
            timestamp = time.strftime("%H:%M:%S")
            chat_log.write(
                f"[dim][{timestamp}] ── Thread opened with @{peer.username} ──[/dim]"
            )

        # Replay any buffered unread messages
        if pending_entry and pending_entry.get("messages"):
            for msg in pending_entry["messages"]:
                chat_log.write(
                    f"[bold cyan][@{peer.username}]:[/bold cyan] [white]{msg}[/white]"
                )

        self.refresh_peer_sidebar()

    def action_close_thread(self) -> None:
        self.active_peer = None
        self.backend.session.close_active_thread()

        welcome_view = self.query_one("#welcome-container")
        chat_log = self.query_one("#chat-log", RichLog)
        chat_header = self.query_one("#chat-header", Static)
        message_input = self.query_one("#message-input", Input)

        chat_log.styles.display = "none"
        welcome_view.styles.display = "block"
        chat_header.update("👻 GhostChat • No active thread (Select a peer on the left or type /help)")
        message_input.placeholder = "Type a message or /command... (Esc to unselect, /help for manual)"
        message_input.focus()
        self.refresh_peer_sidebar()

    def action_focus_peers(self) -> None:
        self.query_one("#peer-list", ListView).focus()

    def action_clear_chat(self) -> None:
        chat_log = self.query_one("#chat-log", RichLog)
        chat_log.clear()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, PeerItem):
            self.open_chat_thread(event.item.peer)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        message_input = self.query_one("#message-input", Input)
        message_input.value = ""

        if not text:
            return

        chat_log = self.query_one("#chat-log", RichLog)
        timestamp = time.strftime("%H:%M:%S")

        # Command handling
        if text.startswith("/"):
            self._handle_command(text, chat_log, timestamp)
            return

        # Regular message in active chat thread
        if self.active_peer is not None:
            peer = self.active_peer
            chat_log.write(f"[{timestamp}] [bold blue][You]:[/bold blue] [white]{text}[/white]")
            threading.Thread(
                target=self._send_message_worker,
                args=(peer, text),
                daemon=True,
            ).start()
        else:
            self._show_chat_view_if_hidden()
            chat_log.write(
                f"[yellow][{timestamp}] ⚠ No active chat thread. "
                "Select a peer on the left or use '/msg <target> <text>'.[/yellow]"
            )

    def _show_chat_view_if_hidden(self) -> None:
        self.query_one("#welcome-container").styles.display = "none"
        self.query_one("#chat-log", RichLog).styles.display = "block"

    def _send_message_worker(self, target: Peer, text: str) -> None:
        success = self.backend.send_encrypted_message(target, text, quiet=True)
        timestamp = time.strftime("%H:%M:%S")

        def notify() -> None:
            chat_log = self.query_one("#chat-log", RichLog)
            if success:
                chat_log.write(f"[dim][{timestamp}] [cyan]✓ Delivery ACKed by @{target.username}[/cyan][/dim]")
            else:
                chat_log.write(
                    f"[dim][{timestamp}] [yellow]⚠ Delivery unconfirmed for @{target.username} (timeout or offline)[/yellow][/dim]"
                )

        self.call_from_thread(notify)

    def _handle_command(self, cmd_line: str, chat_log: RichLog, timestamp: str) -> None:
        self._show_chat_view_if_hidden()

        if cmd_line in ("/exit", "/close"):
            self.action_close_thread()
            return

        if cmd_line == "/quit":
            self.action_quit()
            return

        if cmd_line == "/peers":
            peers = self.backend.discovery.peers()
            chat_log.write(f"[{timestamp}] [cyan]INFO Discovered peers: {len(peers)} online[/cyan]")
            for idx, p in enumerate(peers, start=1):
                chat_log.write(f"  {idx}. @{p.username} ({p.ip}:{p.tcp_port})")
            return

        if cmd_line == "/help":
            chat_log.write(f"[bold cyan]── GhostChat Command Manual ──[/bold cyan]")
            chat_log.write("  • [cyan]/peers[/cyan] : Show discovered peers")
            chat_log.write("  • [cyan]/msg <target> <text>[/cyan] : Send one-off encrypted message")
            chat_log.write("  • [cyan]/chat <target>[/cyan] : Open dedicated thread with target")
            chat_log.write("  • [cyan]/sendimg <target> <path>[/cyan] : Send encrypted image")
            chat_log.write("  • [cyan]/sendgif <target> <path>[/cyan] : Send encrypted animated GIF")
            chat_log.write("  • [cyan]/exit[/cyan] : Close current chat thread and return to dashboard")
            chat_log.write("  • [cyan]/quit[/cyan] : Exit GhostChat")
            return

        if cmd_line.startswith("/msg "):
            parts = cmd_line.split(" ", 2)
            if len(parts) < 3:
                chat_log.write("[yellow]Usage: /msg <target> <text>[/yellow]")
                return
            target_token, msg_text = parts[1], parts[2]
            resolved = SessionManager.resolve_target(self.backend.discovery.peers(), target_token)
            if resolved is None:
                chat_log.write(f"[yellow]Peer '{target_token}' not found.[/yellow]")
                return
            if isinstance(resolved, list):
                chat_log.write(f"[yellow]Multiple peers match '{target_token}'. Specify username@port.[/yellow]")
                return
            chat_log.write(f"[{timestamp}] [bold blue][To @{resolved.username}]:[/bold blue] [white]{msg_text}[/white]")
            threading.Thread(target=self._send_message_worker, args=(resolved, msg_text), daemon=True).start()
            return

        if cmd_line.startswith("/chat "):
            target_token = cmd_line.split(" ", 1)[1].strip()
            resolved = SessionManager.resolve_target(self.backend.discovery.peers(), target_token)
            if resolved is None:
                chat_log.write(f"[yellow]Peer '{target_token}' not found.[/yellow]")
                return
            if isinstance(resolved, list):
                chat_log.write(f"[yellow]Multiple peers match '{target_token}'.[/yellow]")
                return
            self.open_chat_thread(resolved)
            return

        if cmd_line.startswith("/sendimg ") or cmd_line.startswith("/sendgif "):
            parts = cmd_line.split(" ")
            media_type = "IMAGE" if parts[0] == "/sendimg" else "GIF"
            if len(parts) == 2 and self.active_peer:
                filepath = parts[1].strip()
                target = self.active_peer
            elif len(parts) >= 3:
                target_token, filepath = parts[1], parts[2].strip()
                target = SessionManager.resolve_target(self.backend.discovery.peers(), target_token)
                if target is None or isinstance(target, list):
                    chat_log.write(f"[yellow]Could not resolve peer '{target_token}'[/yellow]")
                    return
            else:
                chat_log.write(f"[yellow]Usage: {parts[0]} <target> <path> (or {parts[0]} <path> in active thread)[/yellow]")
                return

            if not os.path.exists(filepath):
                chat_log.write(f"[red]File not found: {filepath}[/red]")
                return

            chat_log.write(f"[{timestamp}] [cyan]Sending {media_type} to @{target.username}...[/cyan]")
            threading.Thread(
                target=self.backend.send_media,
                args=(target, filepath, media_type),
                daemon=True,
            ).start()
            return

        chat_log.write(f"[yellow]Unknown command '{cmd_line}'. Type /help for available commands.[/yellow]")
