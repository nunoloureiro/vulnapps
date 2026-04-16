from fastapi.templating import Jinja2Templates
from pathlib import Path

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
# Disable Jinja2 template cache to avoid "unhashable type: dict" error
# in Jinja2 3.1.5+ where globals are included in cache keys
templates.env.cache = None
