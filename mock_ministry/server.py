"""Compatibility entrypoint for the default ministry mock server.

The default server is the protocol-level ministry supervision platform mock.
Future external-system mocks should live under ``mock_ministry.mocks``.
"""

from __future__ import annotations

from .mocks.protocol_ministry_platform.server import ACCEPTED_RESPONSE, create_server, make_handler, serve

__all__ = ["ACCEPTED_RESPONSE", "create_server", "make_handler", "serve"]
