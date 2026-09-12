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


def test_tui_thread_pane_isolation(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        monkeypatch.setattr("ghostchat.crypto.keys.KEY_ROOT_DIR", tmp_path)
        backend = GhostChatApp(username="alice", port=59998)
        tui_app = GhostChatTUIApp(backend=backend)

        import base64
        from nacl.public import PrivateKey

        valid_pk_b64 = base64.b64encode(bytes(PrivateKey.generate().public_key)).decode("utf-8")

        bob = Peer(
            peer_id="bob-id",
            username="bob",
            ip="127.0.0.1",
            tcp_port=59992,
            enc_public_key_b64=valid_pk_b64,
            sign_public_key_b64=valid_pk_b64,
            last_seen=1000.0,
        )

        async with tui_app.run_test(size=(100, 30)) as pilot:
            # 1. Open Bob's thread
            tui_app.open_chat_thread(bob)
            msg_input = tui_app.query_one("#message-input", Input)
            msg_input.value = "Hello Bob direct message"
            await pilot.press("enter")

            # Verify recorded in Bob's history
            bob_msgs = backend.session.get_peer_messages(bob.peer_id)
            assert len(bob_msgs) == 1
            assert bob_msgs[0]["text"] == "Hello Bob direct message"

            # 2. Switch to channel #general
            tui_app.open_channel_thread("#general")
            assert backend.session.active_channel == "#general"
            assert tui_app.active_peer is None

            # Bob's message should NOT be in #general's history
            gen_msgs = backend.session.get_channel_messages("#general")
            assert not any("Hello Bob direct message" in m["text"] for m in gen_msgs)

            # Send in #general
            msg_input.value = "Broadcast in general mesh"
            await pilot.press("enter")
            gen_msgs_after = backend.session.get_channel_messages("#general")
            assert len(gen_msgs_after) >= 1
            assert gen_msgs_after[-1]["text"] == "Broadcast in general mesh"

            # 3. Switch back to Bob's thread
            tui_app.open_chat_thread(bob)
            assert tui_app.active_peer == bob
            assert backend.session.active_channel is None

            # Replayed history contains Bob's message
            bob_msgs_after = backend.session.get_peer_messages(bob.peer_id)
            assert len(bob_msgs_after) == 1
            assert bob_msgs_after[0]["text"] == "Hello Bob direct message"

            # 4. Simulate an incoming message from Charlie while viewing Bob
            charlie = Peer(
                peer_id="charlie-id",
                username="charlie",
                ip="127.0.0.1",
                tcp_port=59993,
                enc_public_key_b64="enc_key_c",
                sign_public_key_b64="sign_key_c",
                last_seen=1000.0,
            )
            routing = backend.session.record_incoming_message(
                sender_peer_id=charlie.peer_id,
                matched_peer=charlie,
                plaintext="Hey Alice from Charlie",
            )
            # Routing must be queued (not active and not clobbering)
            assert routing["action"] == "queued"
            assert routing["unread_count"] == 1

            # Bob's active thread is intact
            assert tui_app.active_peer == bob

    asyncio.run(run())
