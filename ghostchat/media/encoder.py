import os
from PIL import Image

class MediaEncoder:
    def __init__(self, max_width: int = 120, max_height: int = 60):
        self.max_width = max_width
        self.max_height = max_height

    def optimize_image(self, input_path: str, output_path: str) -> str:
        """
        Optimizes image for terminal transfer.
        Returns the path to the optimized file.
        """
        try:
            img = Image.open(input_path)

            # Check if resize is needed
            if img.width > self.max_width or img.height > self.max_height:
                img.thumbnail((self.max_width, self.max_height))

            # For terminal, we don't need super high quality
            # If it's already a small file, maybe just use it?
            # But let's ensure it's in a standard format

            if input_path.lower().endswith(('.gif')):
                # For GIFs, we might want to compress frames but PIL's GIF support is limited for optimization
                # Just save it for now, maybe reduce colors?
                img.save(output_path, save_all=True, optimize=True)
            else:
                img.save(output_path, optimize=True, quality=85)

            return output_path
        except Exception as e:
            print(f"Error optimizing image: {e}")
            return input_path
