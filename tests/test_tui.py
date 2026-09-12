import asyncio
from textual.widgets import Input, ListView, RichLog, Static

from ghostchat.main import GhostChatApp
from ghostchat.network.discovery import Peer
from ghostchat.ui.app import GhostChatTUIApp
from ghostchat.ui.banner import (
    get_identity_card,
    get_styled_logo_text,
    get_welcome_dashboard_renderable,
)


def test_banner_renderables() -> None:
    logo = get_styled_logo_text()
    assert "LAN-first" in logo.plain
    assert "Encrypted" in logo.plain

    card = get_identity_card("alice", 5001, "4a2f8b1c")
    assert card is not None

    dashboard = get_welcome_dashboard_renderable("alice", 5001, "4a2f8b1c")
    assert dashboard is not None


def test_tui_app_mount_and_widgets(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr("ghostchat.crypto.keys.KEY_ROOT_DIR", tmp_path)
        backend = GhostChatApp(username="test_alice", port=59990)
        tui_app = GhostChatTUIApp(backend=backend)

        async with tui_app.run_test() as pilot:
            assert tui_app.query_one("#sidebar") is not None
            assert tui_app.query_one("#peer-list", ListView) is not None
            assert tui_app.query_one("#chat-header", Static) is not None
            assert tui_app.query_one("#welcome-container") is not None
            assert tui_app.query_one("#chat-log", RichLog) is not None
            assert tui_app.query_one("#message-input", Input) is not None

            # Welcome view visible, chat-log hidden initially
            assert tui_app.query_one("#welcome-container").styles.display != "none"
            assert tui_app.query_one("#chat-log", RichLog).styles.display == "none"
            assert tui_app.active_peer is None

    asyncio.run(run())


def test_tui_thread_open_and_close(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr("ghostchat.crypto.keys.KEY_ROOT_DIR", tmp_path)
        backend = GhostChatApp(username="test_alice", port=59991)
        tui_app = GhostChatTUIApp(backend=backend)

        test_peer = Peer(
            peer_id="bob-id",
            username="bob",
            ip="127.0.0.1",
            tcp_port=59992,
            enc_public_key_b64="enc_key",
            sign_public_key_b64="sign_key",
            last_seen=1000.0,
        )

        async with tui_app.run_test() as pilot:
            # Open thread with test_peer
            tui_app.open_chat_thread(test_peer)
            assert tui_app.active_peer == test_peer
            assert tui_app.query_one("#welcome-container").styles.display == "none"
            assert tui_app.query_one("#chat-log", RichLog).styles.display == "block"

            # Check header updated
            header_text = str(tui_app.query_one("#chat-header", Static).render())
            assert "bob" in header_text

            # Close thread
            tui_app.action_close_thread()
            assert tui_app.active_peer is None
            assert tui_app.query_one("#welcome-container").styles.display != "none"
            assert tui_app.query_one("#chat-log", RichLog).styles.display == "none"

    asyncio.run(run())


def test_tui_input_visibility_and_command(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr("ghostchat.crypto.keys.KEY_ROOT_DIR", tmp_path)
        backend = GhostChatApp(username="test_alice", port=59993)
        tui_app = GhostChatTUIApp(backend=backend)

        async with tui_app.run_test(size=(100, 30)) as pilot:
            inp_container = tui_app.query_one("#input-container")
            msg_input = tui_app.query_one("#message-input", Input)
            assert inp_container is not None
            assert msg_input is not None
            # Check container geometry
            assert inp_container.region.height == 4
            assert msg_input.region.height == 3

            # Submit /help command
            msg_input.value = "/help"
            await pilot.press("enter")

            # Chat log should now be visible and contain help info
            assert tui_app.query_one("#welcome-container").styles.display == "none"
            chat_log = tui_app.query_one("#chat-log", RichLog)
            assert chat_log.styles.display == "block"

    asyncio.run(run())
