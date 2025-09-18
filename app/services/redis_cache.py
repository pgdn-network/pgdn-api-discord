"""
Simple Redis caching for lite validation API.
"""

import os
import logging
import redis.asyncio as redis
from typing import Optional

logger = logging.getLogger(__name__)

class RedisCache:
    """Simple Redis cache for lite validation."""

    def __init__(self):
        self.redis = None
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

    async def initialize(self):
        """Initialize Redis connection."""
        try:
            self.redis = redis.from_url(self.redis_url)
            await self.redis.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis = None

    async def close(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()

    async def is_healthy(self) -> bool:
        """Check if Redis is healthy."""
        if not self.redis:
            return False
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis."""
        if not self.redis:
            return None
        try:
            return await self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None

    async def set_with_expiry(self, key: str, value: str, ttl: int) -> bool:
        """Set value in Redis with TTL."""
        if not self.redis:
            return False
        try:
            await self.redis.setex(key, ttl, value)
            return True
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        if not self.redis:
            return False
        try:
            result = await self.redis.delete(key)
            return result > 0
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")
            return False

# Global cache instance
_redis_cache = None

async def get_redis_cache() -> RedisCache:
    """Get global Redis cache instance."""
    global _redis_cache
    if _redis_cache is None:
        _redis_cache = RedisCache()
        await _redis_cache.initialize()
    return _redis_cache

class LiteValidationCache:
    """Cache for lite validation requests."""

    def __init__(self):
        self.default_expiry = int(os.getenv("LITE_TOKEN_EXPIRY_MINUTES", "45")) * 60

    async def _get_redis(self):
        """Get Redis cache instance."""
        return await get_redis_cache()

    async def has_pending_request(self, validator_id: str, discord_user_id: int) -> bool:
        """Check if there's a pending request."""
        cache = await self._get_redis()
        key = f"lite_validation:pending:{validator_id}:{discord_user_id}"
        result = await cache.get(key)
        return result is not None

    async def set_pending_request(self, validator_id: str, discord_user_id: int, token: str = None) -> bool:
        """Set pending request."""
        cache = await self._get_redis()
        key = f"lite_validation:pending:{validator_id}:{discord_user_id}"
        value = token or "pending"
        return await cache.set_with_expiry(key, value, self.default_expiry)

    async def clear_pending_request(self, validator_id: str, discord_user_id: int) -> bool:
        """Clear pending request."""
        cache = await self._get_redis()
        key = f"lite_validation:pending:{validator_id}:{discord_user_id}"
        return await cache.delete(key)

    async def get_pending_request_ttl(self, validator_id: str, discord_user_id: int) -> Optional[int]:
        """Get TTL of pending request (simplified - return default if exists)."""
        if await self.has_pending_request(validator_id, discord_user_id):
            return self.default_expiry
        return None

    async def get_validation_result(self, validator_id: str, token: str) -> Optional[str]:
        """Get cached validation result."""
        if not token:
            return None
        cache = await self._get_redis()
        key = f"lite_validation:validated:{validator_id}:{token}"
        return await cache.get(key)

    async def set_validation_result(self, validator_id: str, token: str, result: str, ttl: int = None) -> bool:
        """Cache validation result."""
        if not token:
            return False
        cache = await self._get_redis()
        key = f"lite_validation:validated:{validator_id}:{token}"
        expiry = ttl or self.default_expiry
        return await cache.set_with_expiry(key, result, expiry)

    async def check_daily_info_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Check daily info limit (1 per minute)."""
        cache = await self._get_redis()
        key = f"lite_info:{discord_user_id}:{validator_id}:minute"
        result = await cache.get(key)
        return result is not None

    async def set_daily_info_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Set daily info limit."""
        cache = await self._get_redis()
        key = f"lite_info:{discord_user_id}:{validator_id}:minute"
        return await cache.set_with_expiry(key, "requested", 60)

    async def check_rescan_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Check rescan limit (1 per minute)."""
        cache = await self._get_redis()
        key = f"lite_rescan:{discord_user_id}:{validator_id}:minute"
        result = await cache.get(key)
        return result is not None

    async def set_rescan_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Set rescan limit."""
        cache = await self._get_redis()
        key = f"lite_rescan:{discord_user_id}:{validator_id}:minute"
        return await cache.set_with_expiry(key, "requested", 60)

    async def check_daily_rescan_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Check daily rescan limit."""
        cache = await self._get_redis()
        key = f"lite_rescan:{discord_user_id}:{validator_id}:daily"
        result = await cache.get(key)
        return result is not None

    async def set_daily_rescan_limit(self, discord_user_id: int, validator_id: str) -> bool:
        """Set daily rescan limit."""
        cache = await self._get_redis()
        key = f"lite_rescan:{discord_user_id}:{validator_id}:daily"
        return await cache.set_with_expiry(key, "requested", 86400)

    async def check_and_mark_user_welcomed(self, discord_user_id: int) -> bool:
        """Check if user is new and mark as welcomed."""
        cache = await self._get_redis()
        key = f"discord_user_welcomed:v1:{discord_user_id}"

        # Check if user exists
        existing = await cache.get(key)
        if existing:
            return False

        # Mark as welcomed with 1-year TTL
        result = await cache.set_with_expiry(key, "welcomed", 31536000)
        return result

    async def check_daily_add_limit(self, discord_user_id: int) -> bool:
        """Check daily add limit (1 per day per user)."""
        cache = await self._get_redis()
        key = f"lite_add:{discord_user_id}:daily"
        result = await cache.get(key)
        return result is not None

    async def set_daily_add_limit(self, discord_user_id: int) -> bool:
        """Set daily add limit."""
        cache = await self._get_redis()
        key = f"lite_add:{discord_user_id}:daily"
        return await cache.set_with_expiry(key, "requested", 86400)

    # Guild Verification Caching
    async def get_guild_verification_status(self, discord_user_id: int) -> Optional[str]:
        """Get guild verification status from Redis cache with database fallback."""
        cache = await self._get_redis()
        key = f"discord.verified:{discord_user_id}"
        result = await cache.get(key)

        # If not in Redis, check database for unexpired verification
        if result is None:
            from app.models.database import get_db_session, DiscordGuildVerification
            from datetime import datetime

            try:
                with get_db_session() as session:
                    verification = session.query(DiscordGuildVerification).filter(
                        DiscordGuildVerification.discord_user_id == discord_user_id
                    ).first()

                    if verification and verification.is_verified:
                        # Check if verification is still valid (not expired)
                        if verification.verified_until and verification.verified_until > datetime.utcnow():
                            # Re-populate Redis cache with remaining TTL
                            remaining_seconds = int((verification.verified_until - datetime.utcnow()).total_seconds())
                            if remaining_seconds > 0:
                                await cache.set_with_expiry(key, "1", remaining_seconds)
                                return "1"

                    # If no valid verification found, return None (not verified)
                    return None
            except Exception as e:
                # Log error but don't fail - just return None
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Database fallback check failed for user {discord_user_id}: {e}")
                return None

        return result

    async def set_guild_verification_success(self, discord_user_id: int, ttl_days: int = 7) -> bool:
        """Set successful guild verification with TTL in days."""
        cache = await self._get_redis()
        key = f"discord.verified:{discord_user_id}"
        ttl_seconds = ttl_days * 86400
        return await cache.set_with_expiry(key, "1", ttl_seconds)

    async def set_guild_verification_failure(self, discord_user_id: int, ttl_minutes: int = 10) -> bool:
        """Set failed guild verification with TTL in minutes (negative cache)."""
        cache = await self._get_redis()
        key = f"discord.verified:{discord_user_id}"
        ttl_seconds = ttl_minutes * 60
        return await cache.set_with_expiry(key, "0", ttl_seconds)

# Global instance
def get_lite_validation_cache() -> LiteValidationCache:
    """Get lite validation cache instance."""
    return LiteValidationCache()