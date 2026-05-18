import os
from ghostchat.media.chunking import ChunkManager
from ghostchat.media.ascii_renderer import ASCIIRenderer
from ghostchat.media.gif_renderer import GIFRenderer

class MediaDecoder:
    def __init__(self, storage_base: str):
        self.storage_base = storage_base
        self.chunk_manager = ChunkManager()
        self.ascii_renderer = ASCIIRenderer()
        self.gif_renderer = GIFRenderer(self.ascii_renderer)

        self.image_dir = os.path.join(storage_base, "images")
        self.gif_dir = os.path.join(storage_base, "gifs")

        os.makedirs(self.image_dir, exist_ok=True)
        os.makedirs(self.gif_dir, exist_ok=True)

    def handle_chunk(self, sender_peer_id: str, message_id: str, chunk_index: int, total_chunks: int, data: bytes, media_type: str, filename: str):
        is_complete = self.chunk_manager.add_chunk(sender_peer_id, message_id, chunk_index, total_chunks, data)

        if is_complete:
            full_data = self.chunk_manager.reassemble(sender_peer_id, message_id)
            if full_data:
                save_path = self._save_media(full_data, media_type, filename)
                self.chunk_manager.cleanup(sender_peer_id, message_id)
                return save_path
        return None

    def _save_media(self, data: bytes, media_type: str, filename: str) -> str:
        target_dir = self.image_dir if media_type == "IMAGE" else self.gif_dir
        save_path = os.path.join(target_dir, filename)

        # Avoid overwriting if possible, add index
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(save_path):
            save_path = os.path.join(target_dir, f"{base}_{counter}{ext}")
            counter += 1

        with open(save_path, "wb") as f:
            f.write(data)
        return save_path

    def render_media(self, filepath: str, media_type: str):
        if media_type == "IMAGE":
            self.ascii_renderer.render_from_path(filepath)
        elif media_type == "GIF":
            self.gif_renderer.render_gif(filepath)
