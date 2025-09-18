"""
Utility functions for the application.
"""

from fastapi import Request
from typing import Optional


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from FastAPI request.

    Handles various headers from proxies and load balancers.

    Args:
        request: FastAPI Request object

    Returns:
        Client IP address as string
    """
    # Check for forwarded headers first (from load balancers/proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, first one is the original client
        return forwarded_for.split(",")[0].strip()

    # Check for real IP header (some proxies use this)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Check for Cloudflare connecting IP
    cf_connecting_ip = request.headers.get("CF-Connecting-IP")
    if cf_connecting_ip:
        return cf_connecting_ip.strip()

    # Fall back to direct client IP
    client_host = getattr(request.client, 'host', None) if request.client else None
    if client_host:
        return client_host

    # Ultimate fallback
    return "unknown"