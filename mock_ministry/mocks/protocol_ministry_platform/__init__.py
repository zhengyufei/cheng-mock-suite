"""Protocol-level mock for the ministry supervision platform."""

from .contracts import (
    BACKEND_FILE_PATH,
    BACKEND_RECEIVE_PATH,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
    PLATFORM_FILE_PATH,
    PLATFORM_RECEIVE_PATH,
)
from .server import ACCEPTED_RESPONSE, create_server, serve

__all__ = [
    "ACCEPTED_RESPONSE",
    "BACKEND_FILE_PATH",
    "BACKEND_RECEIVE_PATH",
    "LEGACY_PLATFORM_FILE_UPLOAD_PATH",
    "PLATFORM_FILE_PATH",
    "PLATFORM_RECEIVE_PATH",
    "create_server",
    "serve",
]

