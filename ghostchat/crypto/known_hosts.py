import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple


class KnownHostsManager:
    """Manages Trust-On-First-Use (TOFU) key pinning for peer identities.
    
    Persists known peers to ~/.ghostchat/<profile>/known_hosts.json with
    strict 0600 file permissions.
    """

    def __init__(self, key_dir: Path) -> None:
        self.file_path = key_dir / "known_hosts.json"
        self._lock = threading.Lock()
        self._hosts: Dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.file_path.exists():
            return
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "hosts" in data:
                    self._hosts = data["hosts"]
        except (OSError, json.JSONDecodeError):
            self._hosts = {}

    def _save(self) -> None:
        data = {"version": 1, "hosts": self._hosts}
        temp_path = self.file_path.with_suffix(".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(temp_path, flags, 0o600)
        try:
            with open(fd, "w", encoding="utf-8", closefd=True) as f:
                json.dump(data, f, indent=2)
            os.replace(temp_path, self.file_path)
            os.chmod(self.file_path, 0o600)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise

    def check_or_pin(
        self,
        peer_id: str,
        username: str,
        enc_public_key: str,
        sign_public_key: str,
    ) -> Tuple[bool, Optional[str]]:
        """Verify peer keys against pinned records or pin them on first contact.
        
        Returns:
            (True, None) if trusted (pinned or matching).
            (False, warning_message) if key mismatch detected.
        """
        now = time.time()
        with self._lock:
            existing = self._hosts.get(peer_id)
            if existing is None:
                # First time seen: pin identity (TOFU)
                self._hosts[peer_id] = {
                    "username": username,
                    "enc_public_key": enc_public_key,
                    "sign_public_key": sign_public_key,
                    "first_seen": now,
                    "last_seen": now,
                }
                self._save()
                return True, None

            # Verify against pinned keys
            pinned_enc = existing.get("enc_public_key")
            pinned_sign = existing.get("sign_public_key")

            if pinned_enc != enc_public_key or pinned_sign != sign_public_key:
                err = (
                    f"SECURITY ALERT: Cryptographic identity for peer '{username}' ({peer_id}) "
                    f"has changed! Possible Man-In-The-Middle (MITM) attack or unverified key rotation."
                )
                return False, err

            # Update last seen and username if changed
            existing["last_seen"] = now
            if existing.get("username") != username:
                existing["username"] = username
            self._save()
            return True, None

    def get_host(self, peer_id: str) -> Optional[dict]:
        with self._lock:
            return self._hosts.get(peer_id)
