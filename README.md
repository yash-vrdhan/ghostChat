
```text
    .-.     ____ _               _    ____ _           _   
  .'   `.  / ___| |__   ___  ___| |_ / ___| |__   __ _| |_ 
 :       :| |  _| '_ \ / _ \/ __| __| |   | '_ \ / _` | __|
 : O   O :| |_| | | | | (_) \__ \ |_| |___| | | | (_| | |_ 
 :  (_)  : \____|_| |_|\___/|___/\__|\____|_| |_|\__,_|\__|
  `~"~"~`  LAN-first End-to-End Encrypted P2P Terminal Messenger
```

# GhostChat

**GhostChat** is a LAN-first, end-to-end encrypted peer-to-peer terminal chat application built for distributed systems and applied cryptography.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Cryptography-PyNaCl%20%28Ed25519%20%2B%20Curve25519%29-blueviolet)](https://pynacl.readthedocs.io/)
[![TUI](https://img.shields.io/badge/UI-Textual%20TUI-00f0ff)](https://textual.textualize.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[**🚀 Quickstart Guide (Step-by-Step with Screenshots)**](QUICKSTART.md) • [**📘 Deep Dive & Architecture Guide**](LEARNING_AND_IMPLEMENTATION.md)

<p align="center">
  <img src="docs/assets/01_welcome_dashboard.png" alt="GhostChat Welcome Dashboard" width="850">
</p>

---

## 🚀 2-Minute Quickstart

Want to see GhostChat in action immediately? Follow the steps below or check out the full [**Quickstart Guide**](QUICKSTART.md).

```bash
# 1. Install dependencies
poetry install

# 2. Terminal 1: Launch Alice's node
poetry run ghostchat --username alice --port 5001

# 3. Terminal 2: Launch Bob's node
poetry run ghostchat --username bob --port 5002
```

Both nodes will automatically discover each other via LAN UDP broadcast (`:54545`), exchange and verify Ed25519 signatures, and pin keys (TOFU). Select a peer from the sidebar to open an encrypted chat thread!

---

## Feature Set

- **Cryptographic Foundations**:
  - End-to-end encrypted direct messages (Curve25519 via `PyNaCl Box` - XSalsa20 + Poly1305)
  - Signed messages and discovery beacons (Ed25519)
  - Strict POSIX file permissions (`0600` for secret keys, `0700` for profile directories)
  - Trust-On-First-Use (TOFU) host key pinning in `~/.ghostchat/<username>/known_hosts.json`
- **Network, Mesh & Gossip Protocol**:
  - UDP LAN peer discovery with signed broadcast beacons (`:54545`)
  - Persistent TCP sessions per peer (`peer_id -> socket` reuse with write locks)
  - Length-prefixed binary framing (`[4-byte uint32 length][payload]`) with a 64 KB DoS guard
  - Epidemic Gossip Protocol for decentralized group channels (`#general`, `#dev-mesh`) with bounded TTL hop limits
  - LRU Seen Cache (`message_id` deduplication) for broadcast storm suppression
  - Authenticated `SecretBox` (XSalsa20-Poly1305) channel encryption derived via PBKDF2-HMAC-SHA256 for private keyed channels
  - Delivery ACK feedback with timeout handling for direct messages
  - Duplicate message suppression by `message_id`
- **Modern Graphical TUI (Claude Code / Gemini CLI Aesthetic)**:
  - Built with [Textual](https://textual.textualize.io/) featuring custom developer dark styling, neon cyan highlights, and violet accents
  - Custom ASCII Ghost logo and cryptographic identity dashboard
  - Dedicated left sidebar for group channels and active peers with real-time online indicators and unread badges
  - **Isolated Dedicated Conversation Panes**: Switching between channels and peers automatically clears the active pane and replays that conversation's complete chronological history, preventing cross-thread confusion
  - **Non-Intrusive Toast Notifications**: Incoming messages for background threads trigger sleek toast notifications and update sidebar unread badges without polluting the active conversation feed
  - Isolated bottom input dock that completely eliminates prompt clobbering from background network events
  - Seamless view transition between Welcome Dashboard and Active Conversation feeds
  - Dual launch mode: opens full graphical TUI by default; `--cli` flag available for classic line mode
- **Terminal UI & Session State**:
  - Interactive chat thread mode with persistent per-peer and per-channel conversation history
  - Dynamic pending chat switching (`/chat <target>` or sidebar selection)
  - Ambiguity resolution for duplicate usernames (`user@port`, `ip:port`, interactive numbered picker)
- **Encrypted Media Transfer & ASCII Rendering**:
  - Encrypted image (`/sendimg`) and animated GIF (`/sendgif`) transfer
  - Stream chunking (64 KB), per-chunk encryption & signing, and retransmit requests
  - Automatic inline terminal ASCII art rendering upon receipt

---

## How It Works

```
1. Node initializes local keys in ~/.ghostchat/<username>/ (permissions 0600)
2. Node starts TCP server listener
3. Node starts UDP discovery broadcaster & listener
4. Peers broadcast signed DISCOVER packets (peer_id, username, port, public keys, Ed25519 signature)
5. Receiver verifies discovery signature and pins keys in known_hosts.json (TOFU)
6. Sender signs plaintext, encrypts payload, frames with 4-byte length prefix, and transmits over TCP
7. Receiver decodes frame, decrypts payload, verifies Ed25519 signature, checks TOFU, ACKs message_id, and displays message
```

---

## Installation

### Option A: pip (Editable)
```bash
pip install -e .
```

### Option B: Poetry
```bash
poetry install
```

Run with:
```bash
poetry run ghostchat --username alice --port 5001
```

---

## Usage

### Core Commands
- `/peers` — show discovered peers and connection status
- `/help` — show command reference
- `/quit` — exit application

### One-Off Messaging
- `/msg` — interactive recipient picker + message prompt
- `/msg <username> <text>` — send directly by username
- `/msg <username>@<port> <text>` — disambiguate duplicate usernames by port
- `/msg <ip>:<port> <text>` — target directly by host and port

### Media Transfer
- `/sendimg <target> <path>` — send an image with automatic terminal ASCII rendering
- `/sendgif <target> <path>` — send an animated GIF with terminal animation rendering

### Group Channels (Decentralized Gossip Mesh)
- `/channels` — list all subscribed group channels and active member counts
- `/join <#channel> [passkey]` — join or create a decentralized channel (optional end-to-end encryption)
- `/key [channel] <passkey>` — set or unlock channel encryption key (auto-decrypts historical messages)
- `/leave <#channel>` — leave a group channel

### Chat Thread Mode
- `/chat` — show usage or open dedicated thread
- `/chat <target>` — open thread directly (`username`, `username@port`, `ip:port`, or `#channel`)
- `/exit` — close active chat thread and return cleanly to Dashboard

While a thread is active, any plain text entered sends directly to that thread with sign + encrypt + length-prefixed framing + delivery ACK. You can also send `/sendimg <path>` or `/sendgif <path>` directly to the active peer.

---

## Security Model

- **Confidentiality**: All message payloads encrypted end-to-end using Curve25519 (direct 1-on-1) or XSalsa20-Poly1305 `SecretBox` (keyed channels).
- **Authenticity & Integrity**: Ed25519 digital signatures verified on every message, file chunk, discovery broadcast, and gossip packet.
- **Replay & DoS Mitigation**: Duplicate `message_id` suppression, LRU Seen Caching, and strict 64 KB maximum packet size limits over length-prefixed TCP frames.
- **Identity Pinning (TOFU)**: Public keys are pinned upon first contact in `~/.ghostchat/<profile>/known_hosts.json`. Any unannounced key changes trigger explicit security alerts.
- **At-Rest Protection**: Secret key files are locked to `0600` (`-rw-------`) and directories to `0700` (`drwx------`).

---

## Testing

Run the full automated test suite:
```bash
poetry run pytest -v
```

31 automated unit, integration, and TUI tests cover:
- Cryptographic encryption/decryption round-trips
- Signature verification and tamper detection
- Signed discovery beacon generation and spoof rejection
- POSIX file and directory permission invariants (`0600`/`0700`)
- Known-hosts TOFU pinning and MITM change detection
- Length-prefixed framing codec round-trips and oversized packet rejection
- TCP transport delivery, ACKs, connection reuse, and deduplication
- Media chunking, optimization, reconstruction, and ASCII rendering pipeline
- Textual TUI mounting, sidebar peer rendering, and view switching

---

## Repository Layout

- `ghostchat/crypto/` — Key generation, storage security, encryption, signing, and TOFU key pinning
- `ghostchat/network/` — Signed UDP discovery service and length-prefixed TCP transport
- `ghostchat/protocol/` — Typed packet dataclasses and binary framing codecs
- `ghostchat/session/` — Chat thread state machine, unread buffer queue, and target resolution
- `ghostchat/media/` — Image/GIF optimization, 64KB chunking, and terminal ASCII rendering
- `ghostchat/ui/` — Rich terminal rendering panels and dashboards
- `ghostchat/main.py` — Application entry point and interactive coordinator
- `tests/` — Complete unit and integration test suite
- `LEARNING_AND_IMPLEMENTATION.md` — Deep-dive educational architecture and security journal
