from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


GHOST_LOGO = r"""
    .-.     ____ _               _    ____ _           _   
  .'   `.  / ___| |__   ___  ___| |_ / ___| |__   __ _| |_ 
 :       :| |  _| '_ \ / _ \/ __| __| |   | '_ \ / _` | __|
 : O   O :| |_| | | | | (_) \__ \ |_| |___| | | | (_| | |_ 
 :  (_)  : \____|_| |_|\___/|___/\__|\____|_| |_|\__,_|\__|
  `~"~"~`  LAN-first End-to-End Encrypted P2P Terminal Messenger
"""

MINI_LOGO = "👻 [bold cyan]Ghost[/bold cyan][bold magenta]Chat[/bold magenta]"


def get_styled_logo_text() -> Text:
    text = Text()
    lines = GHOST_LOGO.strip("\n").split("\n")
    for i, line in enumerate(lines):
        if i < 5:
            # Ghost part on left, GhostChat text on right
            ghost_part = line[:10]
            name_part = line[10:]
            text.append(ghost_part, style="bold cyan")
            text.append(name_part + "\n", style="bold magenta")
        else:
            # Subtitle line
            ghost_part = line[:10]
            sub_part = line[10:]
            text.append(ghost_part, style="bold cyan")
            text.append(sub_part + "\n", style="dim cyan italic")
    return text


def get_identity_card(username: str, port: int, fingerprint: str) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")

    table.add_row("Identity Node:", f"@{username}")
    table.add_row("TCP Listen Port:", f"{port}")
    table.add_row("Ed25519 Fingerprint:", f"[bold green]{fingerprint}[/bold green]")
    table.add_row("Key Storage:", "POSIX 0600 [dim](~/.ghostchat/)[/dim]")
    table.add_row("Security Model:", "Curve25519 Box + Ed25519 + TOFU Pinning")
    table.add_row("Transport Framing:", "Length-Prefixed Binary (64 KB DoS Limit)")

    return Panel(
        table,
        title="[bold magenta]Cryptographic Node Identity[/bold magenta]",
        border_style="cyan",
        padding=(1, 2),
    )


def get_welcome_dashboard_renderable(username: str, port: int, fingerprint: str) -> Group:
    logo = get_styled_logo_text()
    identity = get_identity_card(username, port, fingerprint)

    hints = Text.from_markup(
        "\n[bold yellow]⚡ Quick Start:[/bold yellow]\n"
        "  • Select a peer from the [cyan]Peers Sidebar[/cyan] on the left to start chatting.\n"
        "  • Or type [cyan]/msg <username> <text>[/cyan] in the input dock below.\n"
        "  • Send encrypted media: [cyan]/sendimg <path>[/cyan] or [cyan]/sendgif <path>[/cyan].\n"
        "  • Press [bold white]Esc[/bold white] to return to this dashboard at any time.\n"
        "  • Type [cyan]/help[/cyan] for the complete command reference.\n"
    )

    return Group(logo, identity, hints)
