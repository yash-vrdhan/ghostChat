# GhostChat

GhostChat is a LAN-first terminal chat application for learning distributed systems and applied cryptography.

It uses peer discovery, persistent peer-to-peer TCP sessions, end-to-end encryption, signatures, and delivery ACKs.

## Current Feature Set
- UDP LAN peer discovery (broadcast)
- Persistent TCP sessions per peer (`peer_id -> socket` reuse)
- End-to-end encrypted direct messages (Curve25519 via `PyNaCl Box`)
- Signed messages (Ed25519)
- ACK-based delivery feedback with timeout handling
- Duplicate message suppression by `message_id`
- Local identity persistence in `~/.ghostchat/<username>/`
- Interactive chat thread mode with pending thread switching

## How It Works
1. Node starts TCP listener
2. Node starts UDP discovery broadcaster + listener
3. Peers exchange `peer_id`, username, port, and public keys
4. Sender signs plaintext, encrypts payload, sends over TCP with `message_id`
5. Receiver decrypts, verifies signature, ACKs message ID, and displays message

## Install

### Option A: pip
```bash
pip install -e .
```

### Option B: Poetry
```bash
poetry install
```

Run with:
```bash
poetry run ghostchat --username yash --port 5001
```

## Usage

### Core commands
- `/peers` show discovered peers
- `/help` show command reference
- `/quit` exit app

### One-off messaging
- `/msg` interactive recipient picker + one message
- `/msg <username> <text>`
- `/msg <username>@<port> <text>`
- `/msg <ip>:<port> <text>`

### Chat thread mode
- `/chat` interactive recipient picker and open thread
- `/chat <target>` open thread directly (`username`, `username@port`, `ip:port`)
- `/chat-thread` alias of `/chat`
- `/chat switch` switch to pending chat via interactive picker
- `/chat switch <target>` switch directly to pending chat
- `/chat pending` list pending chats with unread counts
- `/exit` close current active chat thread

While a thread is active, plain text input sends to that peer with sign+encrypt+ACK.
If ACK fails or peer is offline, thread closes with warning.

## Message Routing Behavior
- If no active thread and a message arrives, GhostChat auto-opens thread with that sender.
- If another peer messages while you are in an active thread, message is queued as pending with unread count.
- Switching to that pending thread displays buffered unread messages.

## Security Model (Current)
- Confidentiality: payload encrypted end-to-end
- Integrity/authenticity: signature verification before display
- Replay mitigation: duplicate `message_id` suppression
- Identity persistence: local keypairs remain stable per username profile

## Known Limitations
- Trust model is still TOFU-like (no key pinning/rotation policy yet)
- LAN scope only (no NAT traversal)
- No offline storage / retries beyond current process
- No group messaging

## Testing
Run all tests:
```bash
poetry run pytest -q
```

Notes:
- Transport integration tests use local sockets.
- In restricted environments, transport tests auto-skip if socket bind is blocked.

## Repository Layout
- `ghostchat/network/` discovery and transport
- `ghostchat/crypto/` keys, encryption, signing
- `ghostchat/ui/` terminal rendering helpers
- `tests/` protocol and crypto tests
