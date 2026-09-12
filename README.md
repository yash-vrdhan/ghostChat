
# GhostChat

GhostChat is a LAN-first terminal chat application for learning distributed systems and applied cryptography.

It uses peer discovery, persistent peer-to-peer TCP sessions, length-prefixed protocol framing, end-to-end encryption, digital signatures, delivery ACKs, and Trust-On-First-Use (TOFU) key pinning.

> 📘 **Deep Dive & Architecture Guide**: Check out [LEARNING_AND_IMPLEMENTATION.md](LEARNING_AND_IMPLEMENTATION.md) for detailed explanations of the systems foundations, vulnerabilities discovered, before/after code comparisons, and future roadmap.

---

## Feature Set

- **Cryptographic Foundations**:
  - End-to-end encrypted direct messages (Curve25519 via `PyNaCl Box` - XSalsa20 + Poly1305)
  - Signed messages and discovery beacons (Ed25519)
  - Strict POSIX file permissions (`0600` for secret keys, `0700` for profile directories)
  - Trust-On-First-Use (TOFU) host key pinning in `~/.ghostchat/<username>/known_hosts.json`
- **Network & Protocol**:
  - UDP LAN peer discovery with signed broadcast beacons (`:54545`)
  - Persistent TCP sessions per peer (`peer_id -> socket` reuse with write locks)
  - Length-prefixed binary framing (`[4-byte uint32 length][payload]`) with a 64 KB DoS guard
  - Delivery ACK feedback with timeout handling
  - Duplicate message suppression by `message_id`
- **Terminal UI & Session State**:
  - Interactive chat thread mode with unread background message buffering
  - Dynamic pending chat switching (`/chat switch`)
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

### Chat Thread Mode
- `/chat` — interactive recipient picker to open a dedicated thread
- `/chat <target>` — open thread directly (`username`, `username@port`, or `ip:port`)
- `/chat-thread` — alias of `/chat`
- `/chat pending` — list pending unread chats with counts
- `/chat switch` — switch to pending chat via interactive picker
- `/chat switch <target>` — switch directly to a pending chat
- `/exit` — close active chat thread

While a thread is active, any plain text entered sends directly to that peer with sign + encrypt + length-prefixed framing + delivery ACK. You can also send `/sendimg <path>` or `/sendgif <path>` directly to the active peer.

---

## Security Model

- **Confidentiality**: All message payloads encrypted end-to-end using Curve25519 authenticated encryption.
- **Authenticity & Integrity**: Ed25519 digital signatures verified on every message, file chunk, and discovery broadcast.
- **Replay & DoS Mitigation**: Duplicate `message_id` suppression and strict 64 KB maximum packet size limits over length-prefixed TCP frames.
- **Identity Pinning (TOFU)**: Public keys are pinned upon first contact in `~/.ghostchat/<profile>/known_hosts.json`. Any unannounced key changes trigger explicit security alerts.
- **At-Rest Protection**: Secret key files are locked to `0600` (`-rw-------`) and directories to `0700` (`drwx------`).

---

## Testing

Run the full automated test suite:
```bash
poetry run pytest -v
```

18 automated unit and integration tests cover:
- Cryptographic encryption/decryption round-trips
- Signature verification and tamper detection
- Signed discovery beacon generation and spoof rejection
- POSIX file and directory permission invariants (`0600`/`0700`)
- Known-hosts TOFU pinning and MITM change detection
- Length-prefixed framing codec round-trips and oversized packet rejection
- TCP transport delivery, ACKs, connection reuse, and deduplication
- Media chunking, optimization, reconstruction, and ASCII rendering pipeline

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
