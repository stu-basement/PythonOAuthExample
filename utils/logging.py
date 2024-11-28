import logging
from typing import Optional

def setup_logging(level: Optional[str] = None) -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=level or "INFO",
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ) 