import time
from PIL import Image, ImageSequence
from rich.console import Console
from rich.live import Live
from rich.text import Text
from ghostchat.media.ascii_renderer import ASCIIRenderer

class GIFRenderer:
    def __init__(self, renderer: ASCIIRenderer = None):
        self.renderer = renderer or ASCIIRenderer()
        self.console = Console()

    def render_gif(self, filepath: str, width: int = 80):
        try:
            img = Image.open(filepath)
            frames = []
            durations = []

            for frame in ImageSequence.Iterator(img):
                # Copy the frame and convert to RGB (or L for grayscale)
                # as some GIFs have palettes that get lost
                frame_data = frame.copy().convert("RGBA")
                ascii_frame = self.renderer.image_to_ascii(frame_data, width)
                frames.append(ascii_frame)
                durations.append(frame.info.get('duration', 100) / 1000.0) # ms to s

            with Live(Text(frames[0]), console=self.console, refresh_per_second=10) as live:
                for i in range(len(frames)):
                    live.update(Text(frames[i]))
                    time.sleep(durations[i])

        except Exception as e:
            self.console.print(f"[red]Error rendering GIF: {e}[/red]")
