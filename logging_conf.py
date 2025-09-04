import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import zipfile

LOG_DIR = Path('logs')
LOG_FILE = LOG_DIR / 'app.log'


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure root logger with console and rotating file handlers.

    Parameters
    ----------
    level : int
        Logging level for the root logger.

    Returns
    -------
    logging.Logger
        The configured root logger.
    """
    logger = logging.getLogger()
    if logger.handlers:
        return logger

    LOG_DIR.mkdir(exist_ok=True)
    logger.setLevel(level)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def export_logs(destination: str | Path) -> str:
    """Export current log files into a zip archive at *destination*.

    Parameters
    ----------
    destination : str or Path
        Path to the zip archive to create.

    Returns
    -------
    str
        Path to the created archive as a string.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file in LOG_DIR.glob('app.log*'):
            zf.write(file, arcname=file.name)
    return str(destination)
