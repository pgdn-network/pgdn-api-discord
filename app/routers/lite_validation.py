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
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from collections import defaultdict, deque
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

# Simple in-memory rate limiting
_rate_limits: Dict[str, deque] = defaultdict(deque)

def check_rate_limit(client_ip: str, path: str, max_requests: int = 5, window: int = 3600) -> bool:
    """Simple in-memory rate limiting."""
    current_time = time.time()
    key = f"{client_ip}:{path}"

    # Clean old requests
    request_times = _rate_limits[key]
    while request_times and current_time - request_times[0] > window:
        request_times.popleft()

    # Check if under limit
    if len(request_times) >= max_requests:
        return False

    # Add current request
    request_times.append(current_time)
    return True

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
            "user_id": discord_user_id,
            "message": message
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
    # Rate limiting
    client_ip = get_client_ip(fastapi_request)
    if not check_rate_limit(client_ip, "/public/validate", max_requests=2, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded."
        )

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
    # Rate limiting
    client_ip = get_client_ip(fastapi_request)
    if not check_rate_limit(client_ip, "/private/claim", max_requests=5, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

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
            # Check max open/pending requests
            open_requests_count = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.discord_user_id == request_data.discord_user_id,
                ValidatorLiteRequest.status.in_([ValidatorLiteRequestStatus.ISSUED, ValidatorLiteRequestStatus.EXPIRED, ValidatorLiteRequestStatus.FAILED])
            ).count()

            if open_requests_count >= 10:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum of 10 open validation requests allowed."
                )

            # Check max validated requests
            validated_requests_count = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.discord_user_id == request_data.discord_user_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
            ).count()

            if validated_requests_count >= 10:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum of 10 validated requests allowed per user."
                )

            # Check if validator exists in the system
            node = session.query(Node).filter(Node.address == request_data.validator_id).first()
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

@private_router.get("/info/{validator_address}", response_model=ValidatorNodeInfoResponse)
async def get_validator_info(
    validator_address: str,
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Get validator node information for Discord slash command.

    Requires that the Discord user has successfully validated the validator
    within the last 90 days. Rate limited to 1 request per minute per user per validator.

    URL: /api/v1/lite/private/info/{validator_address}
    """
    logger.info(f"Discord info request for validator {validator_address} from user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        with get_db_session() as session:
            # Check Discord user authority and daily rate limit
            authorized, node, last_validated, message = await check_discord_authority_and_rate_limit(
                validator_address, discord_user_id, session, cache
            )

            if not authorized:
                if "Rate limit exceeded" in message:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=message
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=message
                    )

            # Set daily rate limit AFTER successful authorization
            await cache.set_daily_info_limit(discord_user_id, validator_address)

            # Query for latest timeseries data by node UUID as node_key
            timeseries_record = session.query(NodeTimeseries).filter(
                NodeTimeseries.node_key == str(node.uuid)
            ).order_by(NodeTimeseries.observed_ts.desc()).first()

            # Prepare comprehensive node data response
            node_data = {
                # Basic node info
                "uuid": str(node.uuid),
                "name": node.name,
                "address": node.address,
                "status": node.status,
                "simple_state": node.simple_state.value if node.simple_state else None,
                "validated": node.validated,
                "discovery_status": node.discovery_status.value if node.discovery_status else None,
                "connectivity_status": node.connectivity_status.value if node.connectivity_status else None,
                "network": node.network,
                "node_type": node.node_type,
                "active": node.active,
                "created_at": node.created_at.isoformat() if node.created_at else None,
                "updated_at": node.updated_at.isoformat() if node.updated_at else None
            }

            # Add active IP addresses if available
            if node.resolved_ips:
                active_ips = [ip.ip_address for ip in node.resolved_ips if ip.active]
                node_data["active_ips"] = active_ips
            else:
                node_data["active_ips"] = []

            # Add timeseries metrics if available
            if timeseries_record:
                node_data.update({
                    "tps": float(timeseries_record.tps) if timeseries_record.tps else None,
                    "cps": float(timeseries_record.cps) if timeseries_record.cps else None,
                    "uptime_status": timeseries_record.uptime_status,
                    "latest_score": timeseries_record.latest_score,
                    "total_cves": timeseries_record.total_cves,
                    "ssh_open": timeseries_record.ssh_open,
                    "docker_open": timeseries_record.docker_open,
                    "rpc_reachable": timeseries_record.rpc_reachable,
                    "observed_ts": timeseries_record.observed_ts.isoformat() if timeseries_record.observed_ts else None,
                })
            else:
                node_data.update({
                    "tps": None,
                    "cps": None,
                    "uptime_status": None,
                    "data_available": False
                })

            return ValidatorNodeInfoResponse(
                success=True,
                validator_address=validator_address,
                discord_user_id=discord_user_id,
                node_data=node_data,
                message="Node information retrieved successfully",
                last_validated=last_validated
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
    # Rate limiting
    client_ip = get_client_ip(fastapi_request)
    if not check_rate_limit(client_ip, "/private/add", max_requests=3, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

    logger.info(f"Validator add request for validator_id: {request_data.validator_id}, discord_user_id: {request_data.discord_user_id}")

    try:
        with get_db_session() as session:
            # Check if validator already exists in the system
            existing_node = session.query(Node).filter(Node.address == request_data.validator_id).first()
            if existing_node:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Validator already exists in system"
                )

            # Basic validator format validation (same as existing validation)
            if not request_data.validator_id or len(request_data.validator_id.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid validator format"
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