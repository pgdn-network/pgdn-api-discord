"""
Discord OAuth2 guild verification router.

Implements secure OAuth2 flow for verifying Discord guild membership.
Results are cached in Redis and persisted in the database.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

# Local imports
from app.utils.oauth_state import generate_state, validate_state, get_state_signing_key
from app.utils.discord_api import DiscordOAuth, DiscordAPIError, get_allowed_guild_ids, get_allowed_test_user_ids
from app.models.database import get_db_session, mark_verified, mark_unverified
from app.services.redis_cache import get_lite_validation_cache

logger = logging.getLogger(__name__)

def create_styled_response(icon: str, title: str, message: str, submessage: str = "") -> str:
    """Create a styled HTML response with dark theme."""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
                color: #e0e0e0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 16px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                text-align: center;
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }}
            .icon {{ font-size: 48px; margin-bottom: 20px; }}
            h1 {{ font-size: 24px; margin-bottom: 16px; font-weight: 600; }}
            p {{ font-size: 16px; line-height: 1.6; margin-bottom: 16px; color: #b0b0b0; }}
            .highlight {{ color: #e0e0e0; font-weight: 500; }}
            .success {{ border-left: 4px solid #00d26a; padding-left: 16px; }}
            .error {{ border-left: 4px solid #f04747; padding-left: 16px; }}
            .warning {{ border-left: 4px solid #faa61a; padding-left: 16px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">{icon}</div>
            <h1>{title}</h1>
            <p class="highlight">{message}</p>
            {f'<p>{submessage}</p>' if submessage else ''}
        </div>
    </body>
    </html>
    """

# Create routers for Discord OAuth endpoints
public_router = APIRouter()  # For OAuth flow (start, callback)
private_router = APIRouter()  # For bot verification checks

# Backward compatibility
router = public_router

# Configuration from environment variables
VERIFY_SUCCESS_TTL_DAYS = int(os.getenv("VERIFY_SUCCESS_TTL_DAYS", "7"))
VERIFY_FAIL_TTL_MINUTES = int(os.getenv("VERIFY_FAIL_TTL_MINUTES", "10"))
MIN_ACCOUNT_AGE_DAYS = int(os.getenv("MIN_ACCOUNT_AGE_DAYS", "7"))


@public_router.get("/start")
async def start_discord_oauth(
    state: str
):
    """
    PUBLIC: Start Discord OAuth2 flow.

    Validates the state parameter and redirects to Discord OAuth2 authorization.

    URL: /api/v1/lite/public/discord/start?state=<state>
    """
    logger.info(f"Starting Discord OAuth flow with state: {state[:10]}...")

    try:
        # Validate state format and freshness
        signing_key = get_state_signing_key()
        logger.info(f"Using signing key: {signing_key[:10]}...")
        logger.info(f"Validating state token: {state[:20]}...")
        is_valid, user_id, error_msg = validate_state(state, signing_key)

        if not is_valid:
            logger.warning(f"Invalid state token: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state parameter: {error_msg}"
            )

        # Create OAuth client and get authorization URL
        oauth = DiscordOAuth()
        auth_url = oauth.get_authorization_url(state)

        logger.info(f"Redirecting user {user_id} to Discord OAuth")
        return RedirectResponse(url=auth_url, status_code=302)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth configuration error"
        )
    except Exception as e:
        logger.error(f"Unexpected error in OAuth start: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start OAuth flow"
        )

@public_router.get("/callback")
async def discord_oauth_callback(
    code: str,
    state: str,
    error: Optional[str] = None
):
    """
    PUBLIC: Handle Discord OAuth2 callback.

    Processes the OAuth2 callback, validates the state, exchanges code for token,
    fetches user guilds, checks membership, and updates Redis + database.

    URL: /api/v1/lite/private/discord/callback?code=...&state=...
    """
    logger.info(f"Received OAuth callback with state: {state[:10]}...")

    # Check for OAuth errors
    if error:
        logger.warning(f"OAuth error from Discord: {error}")
        return HTMLResponse(
            content=create_styled_response(
                "⚠️",
                "Authorization Error",
                "There was an error with the Discord authorization.",
                "You can return to Discord and retry the verification process."
            ),
            status_code=400
        )

    if not code:
        logger.warning("No authorization code received")
        return HTMLResponse(
            content=create_styled_response(
                "⚠️",
                "Missing Authorization Code",
                "No authorization code was received from Discord.",
                "Please try again. You can return to Discord."
            ),
            status_code=400
        )

    try:
        # Validate state token
        signing_key = get_state_signing_key()
        is_valid, user_id, error_msg = validate_state(state, signing_key)

        if not is_valid:
            logger.warning(f"Invalid state in callback: {error_msg}")
            return HTMLResponse(
                content=create_styled_response(
                    "🔒",
                    "Security Error",
                    "The request could not be verified.",
                    "This may be due to an expired or invalid request. Please try again."
                ),
                status_code=400
            )

        logger.info(f"Processing OAuth callback for user {user_id}")

        # Initialize services
        oauth = DiscordOAuth()
        cache = get_lite_validation_cache()
        allowed_guild_ids = get_allowed_guild_ids()

        if not allowed_guild_ids:
            logger.error("No allowed guild IDs configured")
            return HTMLResponse(
                content=create_styled_response(
                    "⚙️",
                    "Configuration Error",
                    "Server configuration error.",
                    "Please contact administrators. You can return to Discord."
                ),
                status_code=500
            )

        # Exchange code for access token
        try:
            token_data = oauth.exchange_code_for_token(code)
            access_token = token_data['access_token']
        except DiscordAPIError as e:
            logger.error(f"Token exchange failed: {e}")
            return HTMLResponse(
                content=create_styled_response(
                    "🔑",
                    "Authentication Error",
                    "Failed to authenticate with Discord.",
                    "Please try again. You can return to Discord."
                ),
                status_code=500
            )

        # Get user info first
        try:
            user_info_response = oauth.get_user_info(access_token)

            # Calculate account age from Discord snowflake ID
            discord_id = int(user_info_response.get('id', user_id))
            discord_epoch = 1420070400000  # Discord epoch (January 1, 2015)
            timestamp = ((discord_id >> 22) + discord_epoch) / 1000
            account_created = datetime.fromtimestamp(timestamp)
            account_age_days = (datetime.utcnow() - account_created).days

            logger.info(f"User {user_info_response.get('username')} - Account age: {account_age_days} days ({account_age_days // 365} years), Email verified: {user_info_response.get('verified', 'Unknown')}")

            # Check if user ID is in test allowlist (bypasses all verification)
            allowed_user_ids = get_allowed_test_user_ids()
            current_user_id = str(user_id)  # Convert to string for comparison

            if current_user_id in allowed_user_ids:
                logger.info(f"User ID '{current_user_id}' ({user_info_response.get('username', 'unknown')}) is in test allowlist - bypassing all verification checks")
                # Set flag to bypass verification and use existing success logic
                is_member = True
                matched_guilds = ["allowlist"]  # Dummy value for logging
            else:
                # Check account age requirement
                if account_age_days < MIN_ACCOUNT_AGE_DAYS:
                    logger.warning(f"User {user_id} account too young: {account_age_days} days (minimum: {MIN_ACCOUNT_AGE_DAYS} days)")

                    # Set negative cache in Redis
                    await cache.set_guild_verification_failure(user_id, VERIFY_FAIL_TTL_MINUTES)

                    # Update database
                    try:
                        with get_db_session() as session:
                            mark_unverified(session, user_id, allowed_guild_ids)
                    except Exception as e:
                        logger.error(f"Database update failed for user {user_id}: {e}")

                    # Note: Failure notifications handled by bot's verification system

                    return HTMLResponse(
                        content=create_styled_response(
                            "⏰",
                            "Account Too New",
                            f"Your Discord account must be at least {MIN_ACCOUNT_AGE_DAYS} days old to be verified.",
                            f"Your account is {account_age_days} days old. Please try again in {MIN_ACCOUNT_AGE_DAYS - account_age_days} days."
                        ),
                        status_code=200
                    )

                # Get user's guilds for non-allowlist users
                try:
                    user_guilds = oauth.get_user_guilds(access_token)
                    logger.info(f"User {user_id} is in {len(user_guilds)} Discord servers:")
                    for guild in user_guilds:
                        logger.info(f"  - {guild['name']} (ID: {guild['id']})")
                except DiscordAPIError as e:
                    logger.error(f"Failed to fetch user guilds: {e}")
                    return HTMLResponse(
                        content=create_styled_response(
                            "🌐",
                            "API Error",
                            "Failed to fetch your Discord server information.",
                            "Please try again. You can return to Discord."
                        ),
                        status_code=500
                    )

                # Check guild membership
                is_member, matched_guilds = oauth.check_guild_membership(user_guilds, allowed_guild_ids)
                logger.info(f"Allowed guild IDs: {allowed_guild_ids}")
                logger.info(f"User's guild IDs: {[guild['id'] for guild in user_guilds]}")
                logger.info(f"Matched guilds: {matched_guilds}")

        except Exception as e:
            logger.warning(f"Failed to fetch user info: {e}")
            # Continue without account age check if user info fails
            # Default to normal guild verification for non-allowlist users
            try:
                user_guilds = oauth.get_user_guilds(access_token)
                is_member, matched_guilds = oauth.check_guild_membership(user_guilds, allowed_guild_ids)
            except:
                is_member, matched_guilds = False, []

        if is_member:
            # User is in at least one allowed guild - SUCCESS
            logger.info(f"User {user_id} verified in guilds: {matched_guilds}")

            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(days=VERIFY_SUCCESS_TTL_DAYS)

            # Update Redis cache
            await cache.set_guild_verification_success(user_id, VERIFY_SUCCESS_TTL_DAYS)

            # Update database
            try:
                with get_db_session() as session:
                    mark_verified(session, user_id, expires_at, allowed_guild_ids)
                logger.info(f"Database updated for successful verification of user {user_id}")
            except Exception as e:
                logger.error(f"Database update failed for user {user_id}: {e}")
                # Continue - Redis cache is set, so bot can still work

            # Send success notification via webhook (optional, failures don't affect response)
            try:
                from app.routers.lite_validation import send_discord_validation_success_notification
                send_discord_validation_success_notification(user_id, "Discord verification")
            except Exception as e:
                logger.warning(f"Failed to send success notification to user {user_id}: {e}")

            return HTMLResponse(
                content=create_styled_response(
                    "✅",
                    "Verification Complete",
                    "Congratulations! Your guild membership has been verified successfully.",
                    "You can return to Discord and use the bot commands."
                ),
                status_code=200
            )

        else:
            # User is not in any allowed guild - FAILURE
            logger.info(f"User {user_id} not found in any allowed guilds")

            # Set negative cache in Redis
            await cache.set_guild_verification_failure(user_id, VERIFY_FAIL_TTL_MINUTES)

            # Update database
            try:
                with get_db_session() as session:
                    mark_unverified(session, user_id, allowed_guild_ids)
                logger.info(f"Database updated for failed verification of user {user_id}")
            except Exception as e:
                logger.error(f"Database update failed for user {user_id}: {e}")

            # Note: Failure notifications handled by bot's verification system

            return HTMLResponse(
                content=create_styled_response(
                    "❌",
                    "Verification Failed",
                    "We couldn't confirm your membership in an approved server.",
                    "Please join an approved server and try again."
                ),
                status_code=200
            )

    except Exception as e:
        logger.error(f"Unexpected error in OAuth callback: {e}")
        return HTMLResponse(
            content=create_styled_response(
                "⚠️",
                "Unexpected Error",
                "An unexpected error occurred. Please try again.",
                "If the problem persists, please contact administrators."
            ),
            status_code=500
        )