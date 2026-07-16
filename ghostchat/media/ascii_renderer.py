import numpy as np
from PIL import Image
from rich.console import Console
from rich.text import Text

class ASCIIRenderer:
    # Grayscale characters from darkest to lightest
    DEFAULT_CHARSET = "@%#*+=-:. "

    def __init__(self, charset: str = DEFAULT_CHARSET):
        self.charset = charset
        self.console = Console()

    def image_to_ascii(self, img: Image.Image, width: int = 80) -> str:
        # Calculate height to preserve aspect ratio (ASCII characters are usually taller than wide)
        aspect_ratio = img.height / img.width
        # Factor 0.5 because terminal characters are roughly twice as tall as they are wide
        height = int(width * aspect_ratio * 0.5)

        img = img.resize((width, height)).convert("L")
        pixels = np.array(img)

        ascii_str = ""
        for row in pixels:
            for pixel in row:
                # Map 0-255 to 0-(len(charset)-1)
                char_idx = int(pixel / 256 * len(self.charset))
                ascii_str += self.charset[char_idx]
            ascii_str += "\n"

        return ascii_str

    def render_image(self, img: Image.Image, width: int = 80):
        ascii_text = self.image_to_ascii(img, width)
        self.console.print(Text(ascii_text))

    def render_from_path(self, filepath: str, width: int = 80):
        try:
            img = Image.open(filepath)
            self.render_image(img, width)
        except Exception as e:
            self.console.print(f"[red]Error rendering image: {e}[/red]")
