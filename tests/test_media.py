import os
import time
import threading
import json
import base64
from PIL import Image
import numpy as np

from ghostchat.crypto.keys import load_or_create_keys
from ghostchat.media.encoder import MediaEncoder
from ghostchat.media.decoder import MediaDecoder
from ghostchat.media.chunking import ChunkManager

def test_media_pipeline():
    print("Testing Media Pipeline...")

    # Setup
    user1 = "alice"
    user2 = "bob"
    keys1 = load_or_create_keys(profile=user1)
    keys2 = load_or_create_keys(profile=user2)

    storage1 = f"/tmp/ghostchat_test/{user1}/media"
    storage2 = f"/tmp/ghostchat_test/{user2}/media"
    os.makedirs(storage1, exist_ok=True)
    os.makedirs(storage2, exist_ok=True)

    encoder = MediaEncoder()
    decoder = MediaDecoder(storage2)

    # Create a dummy image
    img_path = "/tmp/ghostchat_test/test.png"
    img = Image.fromarray(np.uint8(np.random.rand(100, 100, 3) * 255))
    img.save(img_path)

    print(f"Original image created at {img_path}")

    # 1. Split and "Send" (simulate)
    chunks = decoder.chunk_manager.split_file(img_path)
    print(f"Split into {len(chunks)} chunks")

    msg_id = "test-msg-id"
    filename = "test.png"

    for i, chunk in enumerate(chunks):
        # Simulate receiving
        save_path = decoder.handle_chunk("alice-peer-id", msg_id, i, len(chunks), chunk, "IMAGE", filename)
        if save_path:
            print(f"Reconstructed image saved to {save_path}")
            assert os.path.exists(save_path)

            # 2. Test rendering (just check if it doesn't crash)
            print("Testing rendering...")
            decoder.render_media(save_path, "IMAGE")

    print("Media Pipeline Test Passed!")

if __name__ == "__main__":
    test_media_pipeline()
