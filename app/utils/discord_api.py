"""
Discord API integration for OAuth2 and guild verification.
"""

import os
import logging
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

logger = logging.getLogger(__name__)

class DiscordAPIError(Exception):
    """Discord API error."""
    pass

class DiscordOAuth:
    """Discord OAuth2 client."""

    def __init__(self):
        self.client_id = os.getenv("OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("OAUTH_CLIENT_SECRET")
        self.redirect_uri = os.getenv("OAUTH_REDIRECT_URI")
        self.oauth_base = os.getenv("OAUTH_BASE", "https://discord.com/api")

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ValueError("Missing required OAuth environment variables")

    def get_authorization_url(self, state: str) -> str:
        """Generate Discord OAuth2 authorization URL."""
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'identify guilds',
            'state': state
        }

        url = f"{self.oauth_base}/oauth2/authorize?" + urlencode(params)
        logger.info(f"Generated authorization URL for state: {state[:10]}...")
        return url

    def exchange_code_for_token(self, code: str) -> Dict:
        """Exchange authorization code for access token."""
        try:
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.redirect_uri
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(
                f"{self.oauth_base}/oauth2/token",
                data=data,
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                raise DiscordAPIError(f"Token exchange failed: {response.status_code}")

            token_data = response.json()
            logger.info("Successfully exchanged code for token")
            return token_data

        except requests.RequestException as e:
            logger.error(f"Request failed during token exchange: {e}")
            raise DiscordAPIError(f"Token exchange request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {e}")
            raise DiscordAPIError(f"Token exchange error: {str(e)}")

    def get_user_info(self, access_token: str) -> Dict:
        """Get user's basic information."""
        try:
            headers = {
                'Authorization': f"Bearer {access_token}",
                'User-Agent': 'DiscordBot (pgdn-api-discord, 1.0)'
            }

            response = requests.get(
                f"{self.oauth_base}/users/@me",
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:
                logger.error(f"User info fetch failed: {response.status_code} - {response.text}")
                raise DiscordAPIError(f"User info fetch failed: {response.status_code}")

            user_info = response.json()
            logger.info(f"Successfully retrieved user info")
            return user_info

        except requests.RequestException as e:
            logger.error(f"Request failed during user info fetch: {e}")
            raise DiscordAPIError(f"User info fetch request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during user info fetch: {e}")
            raise DiscordAPIError(f"User info fetch error: {str(e)}")

    def get_user_guilds(self, access_token: str) -> List[Dict]:
        """Get user's guild memberships."""
        try:
            headers = {
                'Authorization': f"Bearer {access_token}",
                'User-Agent': 'DiscordBot (pgdn-api-discord, 1.0)'
            }

            response = requests.get(
                f"{self.oauth_base}/users/@me/guilds",
                headers=headers,
                timeout=30
            )

            if response.status_code != 200:
                logger.error(f"Guild fetch failed: {response.status_code} - {response.text}")
                raise DiscordAPIError(f"Guild fetch failed: {response.status_code}")

            guilds = response.json()
            logger.info(f"Successfully retrieved {len(guilds)} guilds for user")
            return guilds

        except requests.RequestException as e:
            logger.error(f"Request failed during guild fetch: {e}")
            raise DiscordAPIError(f"Guild fetch request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during guild fetch: {e}")
            raise DiscordAPIError(f"Guild fetch error: {str(e)}")

    def check_guild_membership(self, user_guilds: List[Dict], allowed_guild_ids: List[str]) -> Tuple[bool, List[str]]:
        """Check if user is member of any allowed guilds.

        Args:
            user_guilds: List of guild objects from Discord API
            allowed_guild_ids: List of allowed guild ID strings

        Returns:
            Tuple of (is_member, matched_guild_ids)
        """
        if not allowed_guild_ids:
            logger.warning("No allowed guild IDs configured")
            return False, []

        user_guild_ids = [str(guild['id']) for guild in user_guilds]
        matched_guilds = []

        for guild_id in allowed_guild_ids:
            if guild_id in user_guild_ids:
                matched_guilds.append(guild_id)

        is_member = len(matched_guilds) > 0

        logger.info(f"Guild membership check: {is_member} (matched {len(matched_guilds)} guilds)")
        return is_member, matched_guilds

class DiscordBot:
    """Discord bot client for sending DMs."""

    def __init__(self):
        self.bot_token = os.getenv("BOT_TOKEN")
        self.oauth_base = os.getenv("OAUTH_BASE", "https://discord.com/api")

    def send_dm(self, user_id: int, message: str) -> bool:
        """Send DM to user."""
        if not self.bot_token:
            logger.debug("BOT_TOKEN not configured, skipping DM")
            return False

        try:
            headers = {
                'Authorization': f"Bot {self.bot_token}",
                'Content-Type': 'application/json',
                'User-Agent': 'DiscordBot (pgdn-api-discord, 1.0)'
            }

            # Create DM channel
            dm_data = {'recipient_id': user_id}
            dm_response = requests.post(
                f"{self.oauth_base}/users/@me/channels",
                json=dm_data,
                headers=headers,
                timeout=10
            )

            if dm_response.status_code != 200:
                logger.warning(f"Failed to create DM channel: {dm_response.status_code}")
                return False

            channel_id = dm_response.json()['id']

            # Send message
            message_data = {'content': message}

            msg_response = requests.post(
                f"{self.oauth_base}/channels/{channel_id}/messages",
                json=message_data,
                headers=headers,
                timeout=10
            )

            if msg_response.status_code == 200:
                logger.info(f"Successfully sent DM to user {user_id}")
                return True
            else:
                logger.warning(f"Failed to send DM: {msg_response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending DM to user {user_id}: {e}")
            return False

    def send_success_dm(self, user_id: int, message: str = None) -> bool:
        """Send success DM to user (optional feature)."""
        default_message = "🎉 Congratulations! You have successfully verified your guild membership!"
        return self.send_dm(user_id, message or default_message)

    def send_verification_success_message(self, user_id: int) -> bool:
        """Send verification success message."""
        message = """🎉 **Verification Complete!**

Congratulations! Your Discord account has been successfully verified. You now have access to all verification-required features.

You can now use protected bot commands and access member-only content."""
        return self.send_dm(user_id, message)

    def send_verification_failure_message(self, user_id: int, reason: str = "general") -> bool:
        """Send verification failure message with specific guidance."""
        if reason == "account_age":
            message = """⏰ **Account Too New**

Your Discord account needs to be at least 7 days old to be verified. Please wait until your account matures and try again.

**What you can do:**
• Wait for your account to reach the minimum age
• Retry verification once your account is old enough"""
        elif reason == "guild_membership":
            message = """❌ **Verification Failed**

We couldn't confirm your membership in an approved server. To get verified, you need to join one of these Discord servers:

**Approved Servers:**
• **Mysten Labs** - Official Sui development team
• **Sui Network** - Official Sui blockchain community
• **PGDN** - Our official community server

**What you can do:**
• Join one of the approved servers above
• Make sure you're an active member (not just joined)
• Try verification again after joining

If you believe this is an error, please contact support."""
        else:
            message = """❌ **Verification Failed**

We were unable to verify your Discord account at this time.

**Common requirements:**
• Account must be at least 7 days old
• Must be a member of approved servers (Mysten, Sui, or PGDN)
• Account must be in good standing

Please check these requirements and try again. If you continue having issues, contact support."""

        return self.send_dm(user_id, message)

def get_allowed_guild_ids() -> List[str]:
    """Get allowed guild IDs from environment."""
    guild_ids_str = os.getenv("ALLOWED_GUILD_IDS", "")
    if not guild_ids_str:
        logger.warning("ALLOWED_GUILD_IDS not configured")
        return []

    guild_ids = [gid.strip() for gid in guild_ids_str.split(",") if gid.strip()]
    logger.info(f"Loaded {len(guild_ids)} allowed guild IDs")
    return guild_ids