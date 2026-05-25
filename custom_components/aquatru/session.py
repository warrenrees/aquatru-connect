"""Shared session management utilities for AquaTru integration.

This module provides common session creation functionality used by both
the API client and MQTT client.

Why ThreadedResolver?
--------------------
The default aiohttp DNS resolver (aiodns) has timeout issues on some devices,
particularly Home Assistant Yellow and other embedded systems. ThreadedResolver
uses the system's native DNS resolution in a thread pool, which is more reliable
across different environments.
"""
from __future__ import annotations

import aiohttp
from aiohttp.resolver import ThreadedResolver


def create_session() -> aiohttp.ClientSession:
    """Create an aiohttp session with reliable DNS resolution.

    Uses ThreadedResolver instead of the default aiodns resolver to avoid
    DNS timeout issues on some embedded devices (e.g., Home Assistant Yellow).

    Returns:
        A new aiohttp.ClientSession configured with ThreadedResolver.
    """
    connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
    return aiohttp.ClientSession(connector=connector)
