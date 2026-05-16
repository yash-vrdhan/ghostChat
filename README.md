# GhostChat

GhostChat is a learning-focused, LAN-first, terminal chat app that demonstrates decentralized messaging with end-to-end encryption and signatures.

## Features
- Peer discovery on local network via UDP broadcast
- Direct peer-to-peer messaging over TCP
- E2EE using Curve25519 (`PyNaCl Box`)
- Message signatures using Ed25519
- Persistent local identity keys in `~/.ghostchat`
- Rich terminal UI with peer list and event log

## Architecture
1. Node starts TCP listener
2. Node starts UDP broadcast + discovery listener
3. Peers exchange usernames, ports, and public keys
4. Sender signs plaintext, encrypts for recipient, sends packet
5. Receiver decrypts and verifies signature before display

## Quickstart

### 1. Install
```bash
pip install -e .
```

Or with Poetry:
```bash
poetry install
```

### 2. Run two peers
Terminal A:
```bash
ghostchat --username yash --port 5001
```

Terminal B:
```bash
ghostchat --username alice --port 5003
```

### 3. Chat
- `/peers`
- `/msg <username> <text>`
- `/help`
- `/quit`

## Security Model (Current)
- Confidentiality: message ciphertext only over TCP
- Integrity/authenticity: Ed25519 signature verification
- Key persistence: same local identity across restarts

## Known Limitations
- Trust model is basic (no key pinning / key-change warnings yet)
- LAN scope only
- No NAT traversal or internet routing
- No offline message storage

## Development
Run tests:
```bash
pytest
```

## Roadmap
- Key trust store and key-change detection
- Packet/version schema module
- Better TUI interaction model
- Group messaging protocol
