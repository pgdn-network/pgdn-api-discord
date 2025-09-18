"""
OAuth2 state management utilities for Discord authentication.

Implements secure state token generation and validation using HMAC.
"""

import base64
import hmac
import hashlib
import os
import time
from typing import Tuple, Optional
import logging
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

logger = logging.getLogger(__name__)

def generate_state(user_id: int, signing_key: str) -> str:
    """Generate secure OAuth2 state token.

    Format: base64url(user_id:timestamp:mac)

    Args:
        user_id: Discord user ID
        signing_key: HMAC signing key from environment

    Returns:
        Base64url-encoded state token
    """
    timestamp = int(time.time())

    # Create payload: user_id:timestamp
    payload = f"{user_id}:{timestamp}"

    # Generate HMAC
    mac = hmac.new(
        signing_key.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Create final token: user_id:timestamp:mac
    token = f"{payload}:{mac}"

    # Base64url encode (URL-safe, no padding)
    encoded = base64.urlsafe_b64encode(token.encode('utf-8')).decode('utf-8').rstrip('=')

    logger.info(f"Generated state token for user {user_id}")
    return encoded

def validate_state(state_token: str, signing_key: str, max_age_seconds: int = 600) -> Tuple[bool, Optional[int], str]:
    """Validate OAuth2 state token.

    Args:
        state_token: Base64url-encoded state token
        signing_key: HMAC signing key from environment
        max_age_seconds: Maximum age in seconds (default 10 minutes)

    Returns:
        Tuple of (is_valid, user_id, error_message)
    """
    try:
        # Add padding if needed for base64url decode
        padding = 4 - (len(state_token) % 4)
        if padding != 4:
            state_token += '=' * padding

        # Decode from base64url
        try:
            decoded = base64.urlsafe_b64decode(state_token.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logger.warning(f"Failed to decode state token: {e}")
            return False, None, "Invalid state token format"

        # Parse token: user_id:timestamp:mac
        parts = decoded.split(':')
        if len(parts) != 3:
            logger.warning("State token does not have 3 parts")
            return False, None, "Invalid state token structure"

        try:
            user_id = int(parts[0])
            timestamp = int(parts[1])
            provided_mac = parts[2]
        except ValueError as e:
            logger.warning(f"Failed to parse state token parts: {e}")
            return False, None, "Invalid state token values"

        # Check timestamp freshness
        current_time = int(time.time())
        if current_time - timestamp > max_age_seconds:
            logger.warning(f"State token expired: age={current_time - timestamp}s, max={max_age_seconds}s")
            return False, None, "State token has expired"

        # Recompute HMAC for validation
        payload = f"{user_id}:{timestamp}"

        # Try both hex and base64url formats for compatibility
        expected_mac_hex = hmac.new(
            signing_key.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        expected_mac_b64 = base64.urlsafe_b64encode(
            hmac.new(
                signing_key.encode('utf-8'),
                payload.encode('utf-8'),
                hashlib.sha256
            ).digest()
        ).decode('utf-8').rstrip('=')

        # Constant-time comparison to prevent timing attacks - try both formats
        if not (hmac.compare_digest(provided_mac, expected_mac_hex) or
                hmac.compare_digest(provided_mac, expected_mac_b64)):
            logger.warning("State token HMAC validation failed")
            return False, None, "Invalid state token signature"

        logger.info(f"Successfully validated state token for user {user_id}")
        return True, user_id, "Valid"

    except Exception as e:
        logger.error(f"Unexpected error validating state token: {e}")
        return False, None, "Internal validation error"

def get_state_signing_key() -> str:
    """Get state signing key from environment."""
    key = os.getenv("STATE_SIGNING_KEY")
    if not key:
        raise ValueError("STATE_SIGNING_KEY environment variable not set")
    return key