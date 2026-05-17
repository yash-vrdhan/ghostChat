from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass
class UiEvent:
    level: str
    message: str
    ts: datetime = field(default_factory=datetime.now)


class TerminalUI:
    def __init__(self, username: str, fingerprint: str, port: int) -> None:
        self.username = username
        self.fingerprint = fingerprint
        self.port = port
        self.events: list[UiEvent] = []

    def add_info(self, message: str) -> None:
        self.events.append(UiEvent(level="info", message=message))

    def add_warn(self, message: str) -> None:
        self.events.append(UiEvent(level="warn", message=message))

    def add_message(self, sender: str, text: str) -> None:
        self.events.append(UiEvent(level="msg", message=f"{sender}: {text}"))

    def peers_panel(self, peers: Iterable[object]) -> Panel:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Username")
        table.add_column("Address")
        table.add_column("Last Seen")
        rows = 0
        for p in peers:
            rows += 1
            age = int((datetime.now().timestamp()) - p.last_seen)
            table.add_row(p.username, f"{p.ip}:{p.tcp_port}", f"{age}s ago")
        if rows == 0:
            table.add_row("-", "No peers discovered", "-")
        return Panel(table, title="Peers")

    def logs_panel(self, max_items: int = 14) -> Panel:
        lines = []
        for ev in self.events[-max_items:]:
            prefix = ev.ts.strftime("%H:%M:%S")
            if ev.level == "warn":
                lines.append(Text(f"[{prefix}] WARN  {ev.message}", style="yellow"))
            elif ev.level == "msg":
                lines.append(Text(f"[{prefix}] MSG   {ev.message}", style="white"))
            else:
                lines.append(Text(f"[{prefix}] INFO  {ev.message}", style="cyan"))
        if not lines:
            lines.append(Text("No events yet."))
        return Panel(Group(*lines), title="Event Log")

    def dashboard(self, peers: Iterable[object]) -> Group:
        return Group(
            self.peers_panel(peers),
            Text(
                "Commands: /peers, /msg <username> <text>, /chat, /chat switch, /chat pending, /help, /exit, /quit\n"
            ),
        )
