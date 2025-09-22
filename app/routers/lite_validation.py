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
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, status, Request, Depends, Header
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import and_

# Local imports
from app.utils.helpers import get_client_ip
from app.models.database import (
    get_db_session, Node, NodeIp, ValidatorLiteRequest, ValidatorLiteRequestStatus,
    NodeTimeseries, Organization, get_user_validators as get_user_validators_db
)
from app.models.schemas import (
    ValidatorLiteRequest as ValidatorLiteRequestSchema, ValidatorLiteResponse,
    ValidatorLiteValidationResponse, ValidatorNodeInfoResponse, ValidatorRescanResponse,
    UserWelcomedResponse, ValidatorsListResponse, ValidatorAddResponse,
    FeedbackRequest, FeedbackResponse
)
from app.services.redis_cache import get_lite_validation_cache
from app.services.validator_service import (
    process_validation_request, validate_validator_for_claim, resolve_validator_selection,
    get_user_validators, validate_rescan_authority, log_rescan_request
)

logger = logging.getLogger(__name__)

# Create separate routers for public and private endpoints
public_router = APIRouter()
private_router = APIRouter()

# Configuration from environment variables
LITE_TOKEN_ENABLED = os.getenv("LITE_TOKEN_ENABLED", "true").lower() == "true"
LITE_TOKEN_EXPIRY_MINUTES = int(os.getenv("LITE_TOKEN_EXPIRY_MINUTES", "45"))
BASE_URL = os.getenv("BASE_URL", "https://api.pgdn.ai")
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

        # Handle different message types
        if validator_id == "Discord verification":
            message = "🎉 Congratulations! Your Discord account has been successfully verified! You now have access to all verification-required features.\n\nUse `/start` to get started!"
        else:
            message = f"🎉 Congratulations! You have successfully added **{validator_id}**! Use `/info {validator_id}` to view your validator information."

        payload = {
            "user_id": discord_user_id,
            "message": message
        }

        response = requests.post(
            DISCORD_BOT_WEBHOOK_URL,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code in [200, 204]:
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


def send_discord_validation_failure_notification(discord_user_id: int, validator_id: str, error_message: str) -> bool:
    """Send Discord webhook notification for failed validator validation."""
    if not DISCORD_BOT_WEBHOOK_URL or not DISCORD_API_AUTH_TOKEN:
        logger.warning("Discord webhook URL or token not configured, skipping notification")
        return False

    try:
        headers = {
            "Authorization": f"Bearer {DISCORD_API_AUTH_TOKEN}",
            "Content-Type": "application/json"
        }

        message = f"❌ Validation failed for **{validator_id}**.\n\n**Error:** {error_message}\n\nPlease check your validator setup and try again."

        payload = {
            "user_id": discord_user_id,
            "message": message
        }

        response = requests.post(
            DISCORD_BOT_WEBHOOK_URL,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code in [200, 204]:
            logger.info(f"Successfully sent Discord failure notification to user {discord_user_id} for validator {validator_id}")
            return True
        else:
            logger.warning(f"Discord webhook returned {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Discord failure notification for validator {validator_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending Discord failure notification: {e}")
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
        elif action == "feedback":
            message = f"Feedback from user {discord_user_id}: {validator_id}"
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

        if response.status_code in [200, 204]:
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

        # Check token requirement upfront
        if LITE_TOKEN_ENABLED and not claim:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Claim token is required for validation"
            )

        # Use service layer for validation processing
        with get_db_session() as session:
            success, matched_node_uuid, result_status, message, discord_user_id = process_validation_request(
                validator_id, client_ip, claim, session
            )

        # Log errors but don't raise exceptions
        if result_status == "not_found":
            logger.warning(f"Validation request not found for {validator_id}: {message}")
            if LITE_TOKEN_ENABLED and claim:
                await cache.set_validation_result(validator_id, claim, "not_found")
        elif result_status == "expired":
            logger.warning(f"Validation request expired for {validator_id}: {message}")
        elif result_status == "error":
            logger.error(f"Validation error for {validator_id}: {message}")

        if success and result_status == "validated":
            # Clear pending request from Redis cache
            if discord_user_id:
                await cache.clear_pending_request(validator_id, discord_user_id)

            # Cache the successful validation result
            if LITE_TOKEN_ENABLED and claim:
                await cache.set_validation_result(validator_id, claim, "validated")

            # Send Discord notification to user
            if discord_user_id:
                send_discord_validation_success_notification(discord_user_id, validator_id)

            logger.info(f"Successfully validated validator {validator_id} from IP {client_ip}")

            return ValidatorLiteValidationResponse(
                success=True,
                message=message,
                validator_id=validator_id,
                status="validated"
            )
        else:
            # Clear pending request from Redis cache
            if discord_user_id:
                await cache.clear_pending_request(validator_id, discord_user_id)

            # Cache the failed validation result
            if LITE_TOKEN_ENABLED and claim:
                await cache.set_validation_result(validator_id, claim, "failed")

            # Send Discord failure notification to user
            if discord_user_id:
                send_discord_validation_failure_notification(discord_user_id, validator_id, message)

            logger.warning(f"Validation failed for validator {validator_id} from IP {client_ip}: {message}")

            return ValidatorLiteValidationResponse(
                success=False,
                message=message,
                validator_id=validator_id,
                status=result_status
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
            # Use service layer for validation logic
            is_valid, node, resolved_ip, error_message = validate_validator_for_claim(
                session, request_data.validator_id, request_data.discord_user_id
            )

            if not is_valid:
                if "not found" in error_message.lower():
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=error_message
                    )
                elif "already" in error_message.lower():
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=error_message
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=error_message
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

    Rate limited to 5 requests per minute per user.

    URL: /api/v1/lite/private/info
    """
    logger.info(f"Discord info request for validator {validator_address or 'unspecified'} from user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        with get_db_session() as session:

            # Use service layer for validator selection - allow non-owned validators for info
            success, selected_validator, validator_list, selection_message, user_owns_validator = resolve_validator_selection(
                session, discord_user_id, validator_address, require_ownership=False
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=selection_message
                )

            # If we got a validator list, return it to the user
            if validator_list is not None:
                return ValidatorNodeInfoResponse(
                    success=True,
                    validator_address="multiple",
                    discord_user_id=discord_user_id,
                    message="Multiple validators found. Please specify one.",
                    node_data={"validators": validator_list, "count": len(validator_list)}
                )

            # We have a selected validator
            validator_address = selected_validator

            # Rate limit check - 5 requests per minute for info command
            if await cache.check_command_rate_limit("info", discord_user_id, 5, 60):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. You can use /info up to 5 times per minute."
                )

            # Increment rate limit counter
            await cache.increment_command_counter("info", discord_user_id, 60)

            # Get data from sui_scanner.node_timeseries using ORM
            node_timeseries = session.query(NodeTimeseries).filter(
                NodeTimeseries.hostname == validator_address
            ).order_by(NodeTimeseries.observed_ts.desc()).first()

            if not node_timeseries:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Validator not found"
                )

            if user_owns_validator:
                # Return full data for owned validators
                user_validator = next((v for v in user_validators if v.validator_id == validator_address), None)
                last_validated = user_validator.updated_at if user_validator else None

                node_data = {
                    # Basic info
                    "hostname": node_timeseries.hostname,
                    "ip_or_host": node_timeseries.ip_or_host,
                    "port": node_timeseries.port,
                    "node_key": node_timeseries.node_key,
                    "observed_ts": node_timeseries.observed_ts.isoformat() if node_timeseries.observed_ts else None,

                    # Performance metrics
                    "tps": node_timeseries.tps,
                    "tps_bucket": node_timeseries.tps_bucket,
                    "tps_color": node_timeseries.tps_color,
                    "tps_method": node_timeseries.tps_method,
                    "tps_confidence": node_timeseries.tps_confidence,
                    "cps": node_timeseries.cps,
                    "cps_bucket": node_timeseries.cps_bucket,
                    "cps_color": node_timeseries.cps_color,

                    # Uptime and availability
                    "uptime_status": node_timeseries.uptime_status,
                    "uptime_color": node_timeseries.uptime_color,
                    "uptime_sla_applicable": node_timeseries.uptime_sla_applicable,
                    "uptime_expected": node_timeseries.uptime_expected,

                    # Security metrics
                    "latest_score": node_timeseries.latest_score,
                    "total_cves": node_timeseries.total_cves,
                    "critical_cves": node_timeseries.critical_cves,
                    "high_severity_cves": node_timeseries.high_severity_cves,
                    "total_issues": node_timeseries.total_issues,

                    # Infrastructure details
                    "ssh_open": node_timeseries.ssh_open,
                    "docker_open": node_timeseries.docker_open,
                    "docker_api_accessible": node_timeseries.docker_api_accessible,
                    "unexpected_ports": node_timeseries.unexpected_ports,
                    "unexpected_ports_color": node_timeseries.unexpected_ports_color,
                    "waf_detected": node_timeseries.waf_detected,
                    "metrics_exposed": node_timeseries.metrics_exposed,
                    "tls_enabled": node_timeseries.tls_enabled,
                    "web_server_detected": node_timeseries.web_server_detected,
                    "total_open_ports_count": node_timeseries.total_open_ports_count,

                    # RPC and connectivity
                    "rpc_status": node_timeseries.rpc_status,
                    "rpc_reachable": node_timeseries.rpc_reachable,
                    "rpc_rate_limit_events": node_timeseries.rpc_rate_limit_events,
                    "rpc_methods_count": node_timeseries.rpc_methods_count,
                    "grpc_available": node_timeseries.grpc_available,
                    "websocket_available": node_timeseries.websocket_available,
                    "open_ports_grpc": node_timeseries.open_ports_grpc,
                    "open_grpc_ports": node_timeseries.open_grpc_ports,

                    # Blockchain specific
                    "protocol_version": node_timeseries.protocol_version,
                    "current_epoch": node_timeseries.current_epoch,
                    "checkpoint_height": node_timeseries.checkpoint_height,
                    "chain_identifier": node_timeseries.chain_identifier,
                    "reference_gas_price": node_timeseries.reference_gas_price,
                    "validator_count": node_timeseries.validator_count,
                    "total_stake": node_timeseries.total_stake,

                    # Performance and reliability
                    "response_time_ms": node_timeseries.response_time_ms,
                    "data_completeness_pct": node_timeseries.data_completeness_pct,
                    "rpc_success_rate_pct": node_timeseries.rpc_success_rate_pct,
                    "node_health_score": node_timeseries.node_health_score,
                    "extraction_error_count": node_timeseries.extraction_error_count,
                    "rate_limiting_active": node_timeseries.rate_limiting_active,

                    # Network classification
                    "asn": node_timeseries.asn,

                    # Data quality and metadata
                    "has_tps": node_timeseries.has_tps,
                    "has_cps": node_timeseries.has_cps,
                    "has_uptime": node_timeseries.has_uptime,
                    "missing_reason": node_timeseries.missing_reason,
                    "data_freshness_hours": node_timeseries.data_freshness_hours,
                    "suppress_from_heatmap": node_timeseries.suppress_from_heatmap,
                    "edge": node_timeseries.edge
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
                    node_data={"score": node_timeseries.latest_score}
                )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving validator info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve validator information"
        )

@private_router.get("/rescan", response_model=ValidatorRescanResponse)
@private_router.post("/rescan", response_model=ValidatorRescanResponse)
async def request_validator_rescan(
    discord_user_id: int,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token),
    validator_address: Optional[str] = None
):
    """
    PRIVATE: Request validator rescan for Discord slash command.

    Logic:
    - No address + 0 validators: Error "must provide address"
    - No address + 1 validator: Use that validator for rescan
    - No address + >1 validators: Return validator list
    - With address + owned: Process rescan request

    Requires that the Discord user has successfully validated the validator
    within the last 90 days. Rate limited to 3 requests per minute per user.

    URL: /api/v1/lite/private/rescan (supports both GET and POST)
    """

    logger.info(f"Discord rescan request for validator {validator_address or 'unspecified'} from user {discord_user_id}")

    cache = get_lite_validation_cache()

    try:
        with get_db_session() as session:
            # Step 1: Resolve validator selection using service layer
            success, selected_validator, validator_list, selection_message, user_owns_validator = resolve_validator_selection(
                session, discord_user_id, validator_address
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=selection_message
                )

            # If we got a validator list, return it as an error asking them to specify
            if validator_list is not None:
                validator_names = [v["validator_id"] for v in validator_list]
                message = f"Multiple validators found: {', '.join(validator_names)}. Please specify which one to rescan."
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=message
                )

            # We have a selected validator - proceed with rescan
            final_validator_address = selected_validator

            # Step 2: Check rate limits - 3 requests per minute for rescan command
            if await cache.check_command_rate_limit("rescan", discord_user_id, 3, 60):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. You can use /rescan up to 3 times per minute."
                )

            # Step 3: Validate rescan authority using service layer
            has_authority, validation, authority_message = validate_rescan_authority(
                session, discord_user_id, final_validator_address
            )

            if not has_authority:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=authority_message
                )

            # Step 4: Increment rate limit counter
            await cache.increment_command_counter("rescan", discord_user_id, 60)

            # Step 5: Log rescan request using service layer
            client_ip = get_client_ip(fastapi_request)
            rescan_log_uuid = log_rescan_request(
                session=session,
                validator_address=final_validator_address,
                discord_user_id=discord_user_id,
                node_uuid=str(validation.node_uuid),
                lite_request_uuid=str(validation.uuid),
                client_ip=client_ip
            )

            # Step 6: Send Discord admin notification
            send_discord_admin_notification("rescan", discord_user_id, final_validator_address)

            if rescan_log_uuid:
                logger.info(f"Rescan request logged: {rescan_log_uuid} for validator {final_validator_address}")
            else:
                logger.warning(f"Failed to log rescan request for validator {final_validator_address}")

            # Step 7: Return response
            return ValidatorRescanResponse(
                success=True,
                validator_address=final_validator_address,
                discord_user_id=discord_user_id,
                message="Scanning functionality not available just yet, stay tuned!",
                last_validated=validation.updated_at
            )

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


@private_router.get("/validators")
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
            # Get validators data
            validators_data = get_user_validators_db(session, discord_user_id)

            logger.info(f"Found {validators_data['total_count']} validators for user {discord_user_id}")

            # Return the data directly with success flag added
            return {
                "success": True,
                **validators_data
            }

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
        # Get Redis cache for rate limiting and duplicate prevention
        cache = get_lite_validation_cache()

        # Validate URL format first
        is_valid_url, url_error_message = validate_validator_url(request_data.validator_id)
        if not is_valid_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=url_error_message
            )

        # Check Redis rate limit (10 per day) - consistent with other endpoints
        if await cache.check_command_rate_limit("add", request_data.discord_user_id, 10, 86400):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. You can submit up to 10 validators per day."
            )

        # Check if user already submitted this validator (duplicate prevention)
        if await cache.check_add_request_exists(request_data.discord_user_id, request_data.validator_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"You have already submitted {request_data.validator_id} for review."
            )

        # Check if validator already exists in system using ORM
        with get_db_session() as session:
            existing_node = session.query(Node).filter(
                Node.address == request_data.validator_id
            ).first()

            if existing_node:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Validator already exists in system"
                )

        # All checks passed - set rate limit and duplicate prevention blocks
        await cache.increment_command_counter("add", request_data.discord_user_id, 86400)
        await cache.set_add_request_block(request_data.discord_user_id, request_data.validator_id, 24)

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



@private_router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    request_data: FeedbackRequest,
    fastapi_request: Request,
    token: str = Depends(verify_discord_bot_token)
):
    """
    PRIVATE: Submit user feedback - Discord bot calls this endpoint.

    Allows users to submit feedback messages that are sent to the admin Discord channel.
    Rate limited to 5 submissions per day per user.

    URL: /api/v1/lite/private/feedback
    """
    logger.info(f"Feedback submission from Discord user {request_data.discord_user_id}")

    try:
        # Get Redis cache for rate limiting
        cache = get_lite_validation_cache()

        # Check daily rate limit (5 per day per user)
        if await cache.check_daily_feedback_limit(request_data.discord_user_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Daily feedback limit exceeded. You can only submit 5 feedback messages per day."
            )

        # Increment feedback counter
        await cache.increment_daily_feedback_limit(request_data.discord_user_id)

        # Send feedback to Discord admin channel using existing notification system
        success = send_discord_admin_notification(
            action="feedback",
            discord_user_id=request_data.discord_user_id,
            validator_id=request_data.message  # Reuse validator_id param for message
        )

        if not success:
            logger.warning(f"Failed to send feedback notification for user {request_data.discord_user_id}")
            # Don't fail the request if Discord notification fails

        logger.info(f"Feedback submitted successfully by user {request_data.discord_user_id}")

        return FeedbackResponse(
            success=True,
            message="Feedback submitted successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing feedback submission: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process feedback submission"
        )
