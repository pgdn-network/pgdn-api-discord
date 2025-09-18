"""
Ultra-minimal lite validation API endpoints with separated public/private routes.

URL Structure:
- /api/v1/lite/public/validate/* - Public validation endpoints (no auth required)
- /api/v1/lite/private/* - Private endpoints (Discord bot auth required)
"""

import os
import secrets
import logging
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, status, Request, Depends, Header
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import and_

# Local imports
from app.utils.helpers import get_client_ip
from app.models.database import (
    get_db_session, Node, NodeIp, ValidatorLiteRequest, ValidatorLiteRequestStatus,
    RescanRequestLog, NodeTimeseries, Organization
)
from app.models.schemas import (
    ValidatorLiteRequest as ValidatorLiteRequestSchema, ValidatorLiteResponse,
    ValidatorLiteValidationResponse, ValidatorNodeInfoResponse, ValidatorRescanResponse,
    UserWelcomedResponse, ValidatorsListResponse, ValidatorAddResponse
)
from app.services.redis_cache import get_lite_validation_cache

logger = logging.getLogger(__name__)

# Create separate routers for public and private endpoints
public_router = APIRouter()
private_router = APIRouter()

# Configuration from environment variables
LITE_TOKEN_ENABLED = os.getenv("LITE_TOKEN_ENABLED", "true").lower() == "true"
LITE_TOKEN_EXPIRY_MINUTES = int(os.getenv("LITE_TOKEN_EXPIRY_MINUTES", "45"))
BASE_URL = os.getenv("BASE_URL", "https://api.pgdn.network")
DISCORD_API_AUTH_TOKEN = os.getenv("DISCORD_API_AUTH_TOKEN")
DISCORD_BOT_WEBHOOK_URL = os.getenv("DISCORD_BOT_WEBHOOK_URL", "http://localhost:8080/webhook/send-message")
DISCORD_NOTIFICATION_CHANNEL = os.getenv("DISCORD_NOTIFICATION_CHANNEL")


def verify_discord_bot_token(authorization: Optional[str] = Header(None)) -> str:
    """Verify Discord bot token from Authorization header."""
    if not DISCORD_API_AUTH_TOKEN:
        logger.error("DISCORD_API_AUTH_TOKEN environment variable not set")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Discord bot authentication not configured"
        )

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid scheme")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if token != DISCORD_API_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Discord bot token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token

@private_router.get("/verify/{discord_user_id}")
async def get_verification_status(discord_user_id: int, auth_token: str = Depends(verify_discord_bot_token)):
    """
    PRIVATE: Check Discord user verification status with database fallback.

    Used by Discord bot to check if user is verified. Automatically falls back
    to database when Redis cache is empty and repopulates cache if valid.

    URL: /api/v1/lite/private/verify/{discord_user_id}
    """
    logger.info(f"Checking verification status for user {discord_user_id}")

    try:
        cache = get_lite_validation_cache()
        status = await cache.get_guild_verification_status(discord_user_id)

        if status in ["1", b"1"]:
            logger.info(f"User {discord_user_id} is verified")
            return {"verified": True}
        else:
            logger.info(f"User {discord_user_id} is not verified")
            return {"verified": False}

    except Exception as e:
        logger.error(f"Error checking verification status for user {discord_user_id}: {e}")
        return {"verified": False}

def send_discord_validation_success_notification(discord_user_id: int, validator_id: str) -> bool:
    """Send Discord webhook notification for successful validator validation."""
    if not DISCORD_BOT_WEBHOOK_URL or not DISCORD_API_AUTH_TOKEN:
        logger.warning("Discord webhook URL or token not configured, skipping notification")
        return False

    try:
        headers = {
            "Authorization": f"Bearer {DISCORD_API_AUTH_TOKEN}",
            "Content-Type": "application/json"
        }

        payload = {
            "user_id": discord_user_id,
            "message": f"🎉 Congratulations! You have successfully added **{validator_id}**! Use `/info {validator_id}` to view your validator information."
        }

        response = requests.post(
            DISCORD_BOT_WEBHOOK_URL,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"Successfully sent Discord notification to user {discord_user_id} for validator {validator_id}")
            return True
        else:
            logger.warning(f"Discord webhook returned {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Discord notification for validator {validator_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Discord notification: {e}")
        return False

def send_discord_admin_notification(action: str, discord_user_id: int, validator_id: str) -> bool:
    """Send Discord notification to admin channel for validator actions."""
    if not DISCORD_NOTIFICATION_CHANNEL or not DISCORD_API_AUTH_TOKEN:
        logger.warning("Discord notification channel or token not configured, skipping admin notification")
        return False

    try:
        headers = {
            "Authorization": f"Bearer {DISCORD_API_AUTH_TOKEN}",
            "Content-Type": "application/json"
        }

        if action == "add":
            message = f"User {discord_user_id} wants to add validator: {validator_id}"
        elif action == "rescan":
            message = f"User {discord_user_id} requested rescan for: {validator_id}"
        else:
            message = f"User {discord_user_id} performed {action} on validator: {validator_id}"

        payload = {
            "content": message
        }

        response = requests.post(
            DISCORD_NOTIFICATION_CHANNEL,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"Successfully sent Discord admin notification for {action} by user {discord_user_id}")
            return True
        else:
            logger.warning(f"Discord admin notification returned {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Discord admin notification for {action}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Discord admin notification: {e}")
        return False

def validate_validator_url(validator_id: str) -> tuple[bool, str]:
    """Validate that validator_id is a proper hostname/domain format."""
    import re

    if not validator_id or len(validator_id.strip()) == 0:
        return False, "Validator URL cannot be empty"

    validator_id = validator_id.strip().lower()

    # Must be valid hostname/domain format with at least one dot
    # Pattern: subdomain.domain.tld or domain.tld
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'

    if not re.match(hostname_pattern, validator_id):
        return False, "Invalid hostname/domain format. Please provide a valid validator URL (e.g. validator.example.com)"

    # Additional checks
    if len(validator_id) > 253:  # Max hostname length
        return False, "Hostname too long"

    # Must contain at least one dot (reject single words like "asdfasdf")
    if '.' not in validator_id:
        return False, "Invalid hostname/domain format. Please provide a valid validator URL (e.g. validator.example.com)"

    return True, "Valid URL format"

def validate_validator_ip(validator_id: str, client_ip: str, session: Session) -> tuple[bool, Optional[str], Optional[str]]:
    """Validate that client IP matches a node with the given validator_id."""
    try:
        # Find node by validator_id (matching nodes.address)
        node = session.query(Node).filter(Node.address == validator_id).first()

        if not node:
            logger.info(f"No node found with address matching validator_id: {validator_id}")
            return False, None, f"No node found with address '{validator_id}'"

        logger.info(f"Found node {node.uuid} for validator_id {validator_id}")

        # Check if client IP matches any active IPs for this node
        nodes_with_matching_ip = session.query(Node).options(
            selectinload(Node.resolved_ips),
        ).join(
            NodeIp, Node.id == NodeIp.node_id
        ).filter(
            and_(
                Node.organization_uuid == node.organization_uuid,
                NodeIp.ip_address == client_ip,
                NodeIp.active == True
            )
        ).all()

        # Check if our specific node is in the list
        matching_node = next((n for n in nodes_with_matching_ip if n.uuid == node.uuid), None)

        if matching_node:
            logger.info(f"IP validation successful: {client_ip} matches node {node.uuid}")
            return True, str(node.uuid), None
        else:
            logger.info(f"IP validation failed: {client_ip} does not match any active IPs for node {node.uuid}")
            return False, str(node.uuid), f"IP address {client_ip} does not match any registered IPs for validator {validator_id}"

    except Exception as e:
        logger.error(f"Error during IP validation for validator {validator_id}: {e}")
        return False, None, "Internal error during validation"

async def check_discord_authority_and_rate_limit(
    validator_address: str,
    discord_user_id: int,
    session: Session,
    cache
) -> tuple[bool, Optional[Node], Optional[datetime], str]:
    """Check Discord user authority and daily rate limit for validator info access."""
    try:
        # Check rate limit first (1 per minute)
        if await cache.check_daily_info_limit(discord_user_id, validator_address):
            return False, None, None, "Rate limit exceeded. Please wait 1 minute before trying again."

        # Check 90-day validation authority
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        validation = session.query(ValidatorLiteRequest).filter(
            ValidatorLiteRequest.validator_id == validator_address,
            ValidatorLiteRequest.discord_user_id == discord_user_id,
            ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED,
            ValidatorLiteRequest.updated_at >= ninety_days_ago
        ).order_by(ValidatorLiteRequest.updated_at.desc()).first()

        if not validation:
            return False, None, None, "No valid validation found within 90 days."

        # Get node data using the node_uuid from validation
        node = session.query(Node).filter(Node.uuid == validation.node_uuid).first()
        if not node:
            return False, None, None, "Associated node not found."

        return True, node, validation.updated_at, "Authorized"

    except Exception as e:
        logger.error(f"Error during Discord authority check: {e}")
        return False, None, None, "Internal error during authorization"

# =============================================================================
# PUBLIC ENDPOINTS (No Authentication Required)
# Path: /api/v1/lite/public/*
# =============================================================================

@public_router.get("/validate/{validator_id}", response_model=ValidatorLiteValidationResponse)
async def validate_validator_ownership(
    validator_id: str,
    fastapi_request: Request,
    claim: Optional[str] = None
):
    """
    PUBLIC: Validate validator ownership - Validator operator calls this from their server.

    This endpoint validates that the request is coming from the expected IP address for the validator.
    If token is enabled, also validates the claim token.

    URL: /api/v1/lite/public/validate/{validator_id}
    """
    client_ip = get_client_ip(fastapi_request)
    logger.info(f"Public validation attempt for validator_id: {validator_id}")

    cache = get_lite_validation_cache()

    try:
        # Check Redis cache first for existing validation result
        if LITE_TOKEN_ENABLED and claim:
            cached_result = await cache.get_validation_result(validator_id, claim)
            if cached_result:
                if cached_result == "validated":
                    return ValidatorLiteValidationResponse(
                        success=True,
                        message="Validator ownership already validated.",
                        validator_id=validator_id,
                        status="validated"
                    )
                elif cached_result == "failed":
                    return ValidatorLiteValidationResponse(
                        success=False,
                        message="Validator ownership validation failed.",
                        validator_id=validator_id,
                        status="failed"
                    )

        with get_db_session() as session:
            # First check if any pending request exists for this validator
            any_request = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.validator_id == validator_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.ISSUED
            ).first()

            if not any_request:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Validation request not found"
                )

            # If tokens are enabled, check token requirements
            if LITE_TOKEN_ENABLED:
                if not claim:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Claim token is required for validation"
                    )

                # Find request with matching token
                lite_request = session.query(ValidatorLiteRequest).filter(
                    ValidatorLiteRequest.validator_id == validator_id,
                    ValidatorLiteRequest.status == ValidatorLiteRequestStatus.ISSUED,
                    ValidatorLiteRequest.request_token == claim
                ).first()

                if not lite_request:
                    await cache.set_validation_result(validator_id, claim, "not_found")
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Invalid token"
                    )
            else:
                lite_request = any_request

            # Check if request has expired
            if lite_request.is_expired():
                lite_request.mark_expired()
                session.commit()
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Validation request has expired"
                )

            # Perform real IP validation against node infrastructure
            validation_success, matched_node_uuid, error_message = validate_validator_ip(
                validator_id=validator_id,
                client_ip=client_ip,
                session=session
            )

            if validation_success:
                lite_request.mark_validated(client_ip, matched_node_uuid)
                session.commit()

                # Clear pending request from Redis cache
                await cache.clear_pending_request(validator_id, lite_request.discord_user_id)

                # Cache the successful validation result
                if LITE_TOKEN_ENABLED and claim:
                    await cache.set_validation_result(validator_id, claim, "validated")

                # Send Discord notification to user
                send_discord_validation_success_notification(lite_request.discord_user_id, validator_id)

                logger.info(f"Successfully validated validator {validator_id} from IP {client_ip}")

                return ValidatorLiteValidationResponse(
                    success=True,
                    message="Validator ownership successfully validated.",
                    validator_id=validator_id,
                    status="validated"
                )
            else:
                lite_request.mark_failed()
                session.commit()

                # Clear pending request from Redis cache
                await cache.clear_pending_request(validator_id, lite_request.discord_user_id)

                # Cache the failed validation result
                if LITE_TOKEN_ENABLED and claim:
                    await cache.set_validation_result(validator_id, claim, "failed")

                logger.warning(f"Validation failed for validator {validator_id} from IP {client_ip}: {error_message}")

                return ValidatorLiteValidationResponse(
                    success=False,
                    message=f"Validator ownership validation failed: {error_message or 'IP address does not match expected validator IPs.'}",
                    validator_id=validator_id,
                    status="failed"
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating lite request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate request"
        )

# =============================================================================
# PRIVATE ENDPOINTS (Discord Bot Authentication Required)
# Path: /api/v1/lite/private/*
# =============================================================================

@private_router.post("/claim", response_model=ValidatorLiteResponse)
async def claim_validator_validation(
    request_data: ValidatorLiteRequestSchema,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Claim validator validation - Discord bot calls this endpoint.

    Creates a validation request for existing validators and returns a URL for the validator operator to call.
    Optionally includes a short-lived token for additional security.

    URL: /api/v1/lite/private/claim
    """

    logger.info(f"Private validation request for validator_id: {request_data.validator_id}, discord_user_id: {request_data.discord_user_id}")

    # Check for duplicate requests using Redis cache
    cache = get_lite_validation_cache()
    if await cache.has_pending_request(request_data.validator_id, request_data.discord_user_id):
        ttl = await cache.get_pending_request_ttl(request_data.validator_id, request_data.discord_user_id)
        ttl_minutes = int(ttl / 60) if ttl else 0
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A pending validation request already exists for this validator and Discord user. Try again in {ttl_minutes} minutes."
        )

    try:
        with get_db_session() as session:
            import time
            start_time = time.time()

            # Check max open/pending requests
            logger.info(f"Starting open requests count query for user {request_data.discord_user_id}")
            open_requests_count = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.discord_user_id == request_data.discord_user_id,
                ValidatorLiteRequest.status.in_([ValidatorLiteRequestStatus.ISSUED, ValidatorLiteRequestStatus.EXPIRED, ValidatorLiteRequestStatus.FAILED])
            ).count()
            logger.info(f"Open requests count query completed in {time.time() - start_time:.2f}s")

            if open_requests_count >= 10:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum of 10 open validation requests allowed."
                )

            # Check max validated requests
            start_time = time.time()
            logger.info(f"Starting validated requests count query for user {request_data.discord_user_id}")
            validated_requests_count = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.discord_user_id == request_data.discord_user_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
            ).count()
            logger.info(f"Validated requests count query completed in {time.time() - start_time:.2f}s")

            if validated_requests_count >= 10:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum of 10 validated requests allowed per user."
                )

            # Check if validator exists in the system
            start_time = time.time()
            logger.info(f"Starting node lookup query for validator {request_data.validator_id}")
            node = session.query(Node).filter(Node.address == request_data.validator_id).first()
            logger.info(f"Node lookup query completed in {time.time() - start_time:.2f}s")
            if not node:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="validator not found"
                )

            # Check if this validator has already been validated by any user
            existing_validation = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.validator_id == request_data.validator_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
            ).first()

            if existing_validation:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This validator has already been claimed."
                )

            # Generate optional claim token
            claim_token = None
            expires_at = None
            if LITE_TOKEN_ENABLED:
                claim_token = secrets.token_urlsafe(32)
                expires_at = datetime.utcnow() + timedelta(minutes=LITE_TOKEN_EXPIRY_MINUTES)

            # Create new validation request
            lite_request = ValidatorLiteRequest(
                validator_id=request_data.validator_id,
                discord_user_id=request_data.discord_user_id,
                corp_email=request_data.corp_email,
                request_token=claim_token,
                expires_at=expires_at,
                status=ValidatorLiteRequestStatus.ISSUED
            )

            session.add(lite_request)
            session.commit()
            session.refresh(lite_request)

            # Set pending request in Redis cache
            await cache.set_pending_request(request_data.validator_id, request_data.discord_user_id, claim_token)

            # Build validation URL with new structure
            if LITE_TOKEN_ENABLED and claim_token:
                validation_url = f"{BASE_URL}/api/v1/lite/public/validate/{request_data.validator_id}?claim={claim_token}"
                dns_fallback = {
                    "name": "pgdn-verify",
                    "value": f"{request_data.validator_id}:{claim_token}"
                }
            else:
                validation_url = f"{BASE_URL}/api/v1/lite/public/validate/{request_data.validator_id}"
                dns_fallback = None

            logger.info(f"Created lite validation request {lite_request.uuid} for validator {request_data.validator_id}")

            return ValidatorLiteResponse(
                validator_id=request_data.validator_id,
                validation_url=validation_url,
                claim_token=claim_token,
                dns_fallback=dns_fallback,
                expires_at=expires_at
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating lite validation request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create validation request"
        )

@private_router.get("/info", response_model=ValidatorNodeInfoResponse)
@private_router.get("/info/{validator_address}", response_model=ValidatorNodeInfoResponse)
async def get_validator_info(
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token),
    validator_address: Optional[str] = None
):
    """
    PRIVATE: Get validator node information for Discord slash command.

    Logic:
    - No address + 0 validators: Error "must provide address"
    - No address + 1 validator: Return full data for that validator
    - No address + >1 validators: Return validator list
    - With address + owned: Return full data
    - With address + not owned: Return score only

    Rate limited to 1 request per minute per user per validator.
    """
    logger.info(f"Discord info request for validator {validator_address or 'unspecified'} from user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        with get_db_session() as session:
            # First, get user's validators from validator_lite_requests
            user_validators = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.discord_user_id == discord_user_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
            ).all()

            validator_count = len(user_validators)

            # Handle case where no validator_address provided
            if not validator_address:
                if validator_count == 0:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="You must provide a validator address"
                    )
                elif validator_count == 1:
                    # Use the single validator they have
                    validator_address = user_validators[0].validator_id
                else:
                    # Return list of validators
                    validator_list = [{"validator_id": v.validator_id, "last_validated": v.updated_at} for v in user_validators]
                    return ValidatorNodeInfoResponse(
                        success=True,
                        validator_address="multiple",
                        discord_user_id=discord_user_id,
                        message="Multiple validators found. Please specify one.",
                        node_data={"validators": validator_list, "count": validator_count}
                    )

            # Check if user owns this validator
            user_owns_validator = any(v.validator_id == validator_address for v in user_validators)

            # Rate limit check for all requests
            if await cache.check_daily_info_limit(discord_user_id, validator_address):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. You can only check validator info once per minute."
                )

            # Set rate limit
            await cache.set_daily_info_limit(discord_user_id, validator_address)

            # Get data from sui_scanner.node_timeseries
            from sqlalchemy import text
            result = session.execute(text(
                "SELECT * FROM sui_scanner.node_timeseries WHERE hostname = :hostname ORDER BY observed_ts DESC LIMIT 1"
            ), {"hostname": validator_address})

            row = result.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Validator not found"
                )

            if user_owns_validator:
                # Return full data for owned validators
                user_validator = next((v for v in user_validators if v.validator_id == validator_address), None)
                last_validated = user_validator.updated_at if user_validator else None

                node_data = {
                    "hostname": row.hostname,
                    "latest_score": row.latest_score,
                    "tps": row.tps,
                    "cps": row.cps,
                    "uptime_status": row.uptime_status,
                    "total_cves": row.total_cves,
                    "ssh_open": row.ssh_open,
                    "docker_open": row.docker_open,
                    "rpc_reachable": row.rpc_reachable,
                    "observed_ts": row.observed_ts.isoformat() if row.observed_ts else None
                }

                return ValidatorNodeInfoResponse(
                    success=True,
                    validator_address=validator_address,
                    discord_user_id=discord_user_id,
                    node_data=node_data,
                    message="Node information retrieved successfully",
                    last_validated=last_validated
                )
            else:
                # Return only score for non-owned validators
                return ValidatorNodeInfoResponse(
                    success=True,
                    validator_address=validator_address,
                    discord_user_id=discord_user_id,
                    message="Score retrieved successfully",
                    node_data={"score": row.latest_score}
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving validator info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve validator information"
        )

@private_router.post("/rescan/{validator_address}")
async def request_validator_rescan(
    validator_address: str,
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Request validator rescan for Discord slash command.

    Requires that the Discord user has successfully validated the validator
    within the last 90 days. Rate limited to 1 request per minute per user per validator.

    URL: /api/v1/lite/private/rescan/{validator_address}
    """
    logger.info(f"Discord rescan request for validator {validator_address} from user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        with get_db_session() as session:
            # Check authority and rate limits
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)

            # Check daily rate limit first
            if await cache.check_daily_rescan_limit(discord_user_id, validator_address):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Daily rescan limit exceeded."
                )

            # Check minute rate limit
            if await cache.check_rescan_limit(discord_user_id, validator_address):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please wait 1 minute."
                )

            # Check 90-day validation authority
            validation = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.validator_id == validator_address,
                ValidatorLiteRequest.discord_user_id == discord_user_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED,
                ValidatorLiteRequest.updated_at >= ninety_days_ago
            ).order_by(ValidatorLiteRequest.updated_at.desc()).first()

            if not validation:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No valid validation found within 90 days."
                )

            # Get node data
            node = session.query(Node).filter(Node.uuid == validation.node_uuid).first()
            if not node:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Associated node not found."
                )

            # Set rescan rate limits
            await cache.set_rescan_limit(discord_user_id, validator_address)
            await cache.set_daily_rescan_limit(discord_user_id, validator_address)

            # Get client IP for logging
            client_ip = get_client_ip(fastapi_request)

            # Log the rescan request to database
            rescan_log = RescanRequestLog(
                validator_id=validator_address,
                discord_user_id=discord_user_id,
                node_uuid=node.uuid,
                lite_request_uuid=validation.uuid,
                ip_address=client_ip
            )
            session.add(rescan_log)
            session.commit()

            # Send Discord admin notification for rescan request
            send_discord_admin_notification("rescan", discord_user_id, validator_address)

            logger.info(f"Rescan request logged: {rescan_log.uuid} for validator {validator_address}")

            # Return not available message
            return {"detail": "Scanning functionality not available just yet, stay tuned!"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing validator rescan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process rescan request"
        )

@private_router.post("/welcomed/{discord_user_id}", response_model=UserWelcomedResponse)
async def check_user_welcomed_status(
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Check if Discord user is new for welcome messaging.

    Uses Redis INCR to atomically track if this is the first time seeing this user.
    Returns {"new": true} for new users, {"new": false} for existing users.
    Sets 1-year TTL on the Redis key.

    URL: /api/v1/lite/private/welcomed/{discord_user_id}
    """
    logger.info(f"Discord welcome status check for user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        # Check and mark user as welcomed using Redis
        is_new_user = await cache.check_and_mark_user_welcomed(discord_user_id)

        logger.info(f"Discord user {discord_user_id} welcome status: {'new' if is_new_user else 'existing'}")

        return UserWelcomedResponse(new=is_new_user)

    except Exception as e:
        logger.error(f"Error checking user welcomed status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check user welcome status"
        )


@private_router.get("/validators", response_model=ValidatorsListResponse)
async def get_user_validators_list(
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Get list of validators for a Discord user.

    Returns all validated validators for the specified Discord user,
    including validator info, status, and metadata.

    URL: /api/v1/lite/private/validators?discord_user_id={user_id}
    """
    logger.info(f"Fetching validators for Discord user {discord_user_id}")

    try:
        with get_db_session() as session:
            from app.models.database import get_user_validators

            # Get validators data
            validators_data = get_user_validators(session, discord_user_id)

            logger.info(f"Found {validators_data['total_count']} validators for user {discord_user_id}")

            return ValidatorsListResponse(
                success=True,
                data=validators_data
            )

    except Exception as e:
        logger.error(f"Error fetching validators for user {discord_user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user validators"
        )


@private_router.post("/add", response_model=ValidatorAddResponse)
async def add_validator_request(
    request_data: ValidatorLiteRequestSchema,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Submit validator for addition to PGDN system - Discord bot calls this endpoint.

    Submits a request to add a new validator to the system. The validator will be reviewed
    by administrators and added manually. User will be notified when the validator is available.

    URL: /api/v1/lite/private/add
    """
    logger.info(f"Validator add request for validator_id: {request_data.validator_id}, discord_user_id: {request_data.discord_user_id}")

    try:
        # Get Redis cache for rate limiting
        cache = get_lite_validation_cache()

        # Check daily rate limit (1 per day per user)
        # Check daily submission limit (10 per day)
        daily_count = 0
        try:
            # Count submissions in last 24 hours instead of using cache flag
            from datetime import datetime, timedelta
            twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)

            with get_db_session() as session:
                daily_count = session.query(ValidatorLiteRequest).filter(
                    ValidatorLiteRequest.discord_user_id == request_data.discord_user_id,
                    ValidatorLiteRequest.created_at >= twenty_four_hours_ago
                ).count()
        except Exception as e:
            logger.warning(f"Could not check daily limit: {e}")

        if daily_count >= 10:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="You have reached the maximum number of validator submissions for today."
            )

        # Validate URL format
        is_valid_url, url_error_message = validate_validator_url(request_data.validator_id)
        if not is_valid_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=url_error_message
            )

        with get_db_session() as session:
            # Check if validator already exists in the system
            existing_node = session.query(Node).filter(Node.address == request_data.validator_id).first()
            if existing_node:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Validator already exists in system"
                )


            # Send Discord admin notification
            send_discord_admin_notification("add", request_data.discord_user_id, request_data.validator_id)

            logger.info(f"Validator add request submitted for {request_data.validator_id} by user {request_data.discord_user_id}")

            return ValidatorAddResponse(
                success=True,
                data={
                    "validator_id": request_data.validator_id,
                    "status": "submitted",
                    "message": "Validator submitted for review. You'll be notified when it's added to the system."
                }
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing validator add request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process add request"
        )