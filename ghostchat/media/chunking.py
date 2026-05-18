import math
import os
from typing import Dict, List, Optional, Tuple

class ChunkManager:
    def __init__(self, chunk_size: int = 64 * 1024):
        self.chunk_size = chunk_size
        # (sender_peer_id, message_id) -> {chunk_index: data}
        self.received_chunks: Dict[Tuple[str, str], Dict[int, bytes]] = {}
        # (sender_peer_id, message_id) -> total_chunks
        self.expected_chunks: Dict[Tuple[str, str], int] = {}

    def split_file(self, filepath: str) -> List[bytes]:
        chunks = []
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        with open(filepath, "rb") as f:
            while True:
                data = f.read(self.chunk_size)
                if not data:
                    break
                chunks.append(data)
        return chunks

    def add_chunk(self, sender_peer_id: str, message_id: str, chunk_index: int, total_chunks: int, data: bytes) -> bool:
        key = (sender_peer_id, message_id)
        if key not in self.received_chunks:
            self.received_chunks[key] = {}
            self.expected_chunks[key] = total_chunks

        self.received_chunks[key][chunk_index] = data
        return len(self.received_chunks[key]) == total_chunks

    def get_missing_chunks(self, sender_peer_id: str, message_id: str) -> List[int]:
        key = (sender_peer_id, message_id)
        if key not in self.expected_chunks:
            return []

        total = self.expected_chunks[key]
        received = self.received_chunks.get(key, {})
        missing = [i for i in range(total) if i not in received]
        return missing

    def reassemble(self, sender_peer_id: str, message_id: str) -> Optional[bytes]:
        key = (sender_peer_id, message_id)
        if not self.is_complete(sender_peer_id, message_id):
            return None

        total = self.expected_chunks[key]
        chunks = self.received_chunks[key]

        full_data = b"".join(chunks[i] for i in range(total))
        return full_data

    def is_complete(self, sender_peer_id: str, message_id: str) -> bool:
        key = (sender_peer_id, message_id)
        if key not in self.expected_chunks:
            return False
        return len(self.received_chunks.get(key, {})) == self.expected_chunks[key]

    def cleanup(self, sender_peer_id: str, message_id: str):
        key = (sender_peer_id, message_id)
        self.received_chunks.pop(key, None)
        self.expected_chunks.pop(key, None)
