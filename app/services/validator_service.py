"""
Validator service module for handling validator business logic.

Separates business logic from router concerns for better maintainability and testing.
"""

import socket
import logging
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, text

from app.models.database import Node, ValidatorLiteRequest, ValidatorLiteRequestStatus, RescanRequestLog

logger = logging.getLogger(__name__)


def resolve_validator_hostname(validator_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Resolve validator hostname to IP address using DNS.

    Args:
        validator_id: The hostname/domain to resolve

    Returns:
        Tuple of (success, resolved_ip, error_message)
    """
    try:
        # Remove any protocol prefix and clean the hostname
        hostname = validator_id.strip().lower()
        if hostname.startswith(('http://', 'https://')):
            hostname = hostname.split('://', 1)[1]
        if '/' in hostname:
            hostname = hostname.split('/')[0]
        if ':' in hostname and not hostname.count(':') > 1:  # Not IPv6
            hostname = hostname.split(':')[0]

        logger.info(f"Resolving DNS for hostname: {hostname}")

        # Perform DNS resolution
        resolved_ip = socket.gethostbyname(hostname)
        logger.info(f"DNS resolution successful: {hostname} -> {resolved_ip}")

        return True, resolved_ip, None

    except socket.gaierror as e:
        error_msg = f"DNS resolution failed for {validator_id}: {str(e)}"
        logger.warning(error_msg)
        return False, None, error_msg

    except Exception as e:
        error_msg = f"Unexpected error during DNS resolution for {validator_id}: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg


def check_validator_exists_and_active(session: Session, validator_id: str) -> Tuple[bool, Optional[Node], Optional[str]]:
    """
    Check if validator exists in the system and is active.

    Args:
        session: Database session
        validator_id: Validator hostname/address to check

    Returns:
        Tuple of (exists_and_active, node, error_message)
    """
    try:
        logger.info(f"Checking if validator exists and is active: {validator_id}")

        # Query only the fields we need to avoid enum issues
        result = session.execute(text(
            "SELECT id, uuid, address, active FROM nodes WHERE address = :address LIMIT 1"
        ), {"address": validator_id})

        row = result.fetchone()
        if not row:
            error_msg = f"Validator not found in system: {validator_id}"
            logger.info(error_msg)
            return False, None, error_msg

        # Check if node is active
        if not row.active:
            error_msg = f"Validator exists but is not active: {validator_id}"
            logger.info(error_msg)
            # Create a simple node-like object for return
            mock_node = type('Node', (), {
                'id': row.id,
                'uuid': row.uuid,
                'address': row.address,
                'active': row.active
            })()
            return False, mock_node, error_msg

        logger.info(f"Validator exists and is active: {validator_id}")
        # Create a simple node-like object for return
        mock_node = type('Node', (), {
            'id': row.id,
            'uuid': row.uuid,
            'address': row.address,
            'active': row.active
        })()
        return True, mock_node, None

    except Exception as e:
        error_msg = f"Database error checking validator {validator_id}: {str(e)}"
        logger.error(error_msg)
        return False, None, error_msg


def check_user_already_has_validator(session: Session, discord_user_id: int, validator_id: str) -> Tuple[bool, Optional[str]]:
    """
    Check if this specific user has already added this validator.

    Args:
        session: Database session
        discord_user_id: Discord user ID to check
        validator_id: Validator ID to check

    Returns:
        Tuple of (user_has_validator, error_message)
    """
    try:
        logger.info(f"Checking if user {discord_user_id} already has validator {validator_id}")

        # Check if this user already has a request for this validator
        existing_request = session.query(ValidatorLiteRequest).filter(
            and_(
                ValidatorLiteRequest.discord_user_id == discord_user_id,
                ValidatorLiteRequest.validator_id == validator_id
            )
        ).first()

        if existing_request:
            # Check the status of the existing request
            if existing_request.status == ValidatorLiteRequestStatus.VALIDATED:
                error_msg = f"You've already added {validator_id} to your account, crack on with the /info command!"
                logger.info(error_msg)
                return True, error_msg
            elif existing_request.status == ValidatorLiteRequestStatus.ISSUED:
                error_msg = f"You already have a pending request for {validator_id}"
                logger.info(error_msg)
                return True, error_msg
            else:
                # Failed or expired requests don't count
                logger.info(f"User {discord_user_id} has failed/expired request for {validator_id}, allowing new request")
                return False, None

        logger.info(f"User {discord_user_id} does not have validator {validator_id}")
        return False, None

    except Exception as e:
        error_msg = f"Database error checking user validator relationship: {str(e)}"
        logger.error(error_msg)
        return True, error_msg  # Err on the side of caution


def validate_validator_for_claim(
    session: Session,
    validator_id: str,
    discord_user_id: int
) -> Tuple[bool, Optional[Node], Optional[str], Optional[str]]:
    """
    Complete validation logic for validator claim requests.

    This function performs all the necessary checks:
    1. Validator exists and is active
    2. DNS resolution works
    3. User doesn't already have this validator

    Args:
        session: Database session
        validator_id: Validator hostname/address to validate
        discord_user_id: Discord user ID making the request

    Returns:
        Tuple of (is_valid, node, resolved_ip, error_message)
    """
    logger.info(f"Starting validator validation for {validator_id} by user {discord_user_id}")

    # 1. Check if validator exists and is active
    exists_and_active, node, error_msg = check_validator_exists_and_active(session, validator_id)
    if not exists_and_active:
        return False, node, None, error_msg

    # 2. Perform DNS resolution
    dns_success, resolved_ip, dns_error = resolve_validator_hostname(validator_id)
    if not dns_success:
        return False, node, None, dns_error

    # 3. Check if user already has this validator
    user_has_validator, user_error = check_user_already_has_validator(session, discord_user_id, validator_id)
    if user_has_validator:
        return False, node, resolved_ip, user_error

    logger.info(f"Validator validation successful for {validator_id} by user {discord_user_id}")
    return True, node, resolved_ip, None


def validate_ip_ownership(validator_id: str, client_ip: str, session: Session) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate that client IP matches a node with the given validator_id.

    Args:
        validator_id: Validator hostname/address to validate
        client_ip: IP address of the client making the request
        session: Database session

    Returns:
        Tuple of (is_valid, matched_node_uuid, error_message)
    """
    try:
        logger.info(f"Starting IP validation for validator {validator_id} from IP {client_ip}")

        # Find node by validator_id using raw SQL to avoid enum issues
        node_result = session.execute(text(
            "SELECT id, uuid, organization_uuid, address FROM nodes WHERE address = :address LIMIT 1"
        ), {"address": validator_id})

        node_row = node_result.fetchone()
        if not node_row:
            logger.info(f"No node found with address matching validator_id: {validator_id}")
            return False, None, f"No node found with address '{validator_id}'"

        logger.info(f"Found node {node_row.uuid} for validator_id {validator_id}")

        # Check if client IP matches any active IPs for this node
        ip_result = session.execute(text("""
            SELECT n.uuid, ni.ip_address
            FROM nodes n
            JOIN node_ips ni ON n.id = ni.node_id
            WHERE n.organization_uuid = :org_uuid
            AND ni.ip_address = :client_ip
            AND ni.active = true
            AND n.uuid = :node_uuid
        """), {
            "org_uuid": node_row.organization_uuid,
            "client_ip": client_ip,
            "node_uuid": node_row.uuid
        })

        matching_ip = ip_result.fetchone()

        if matching_ip:
            logger.info(f"IP validation successful: {client_ip} matches node {node_row.uuid}")
            return True, str(node_row.uuid), None
        else:
            logger.info(f"IP validation failed: {client_ip} does not match any active IPs for node {node_row.uuid}")
            return False, str(node_row.uuid), f"IP address {client_ip} does not match any registered IPs for validator {validator_id}"

    except Exception as e:
        logger.error(f"Error during IP validation for validator {validator_id}: {e}")
        return False, None, "Internal error during validation"


def process_validation_request(
    validator_id: str,
    client_ip: str,
    claim_token: Optional[str],
    session: Session
) -> Tuple[bool, Optional[str], str, str, Optional[int]]:
    """
    Process a complete validation request from a validator.

    Args:
        validator_id: Validator hostname/address
        client_ip: IP address of the requesting client
        claim_token: Optional claim token for verification
        session: Database session

    Returns:
        Tuple of (success, matched_node_uuid, status, message, discord_user_id)
    """
    try:
        logger.info(f"Processing validation request for {validator_id} from IP {client_ip}")

        # Check if any pending request exists for this validator

        # Find request with matching token (if tokens enabled) or any pending request
        if claim_token:
            lite_request = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.validator_id == validator_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.ISSUED,
                ValidatorLiteRequest.request_token == claim_token
            ).first()

            if not lite_request:
                return False, None, "not_found", "Invalid token", None
        else:
            lite_request = session.query(ValidatorLiteRequest).filter(
                ValidatorLiteRequest.validator_id == validator_id,
                ValidatorLiteRequest.status == ValidatorLiteRequestStatus.ISSUED
            ).first()

            if not lite_request:
                return False, None, "not_found", "Validation request not found", None

        # Store discord_user_id for return
        discord_user_id = lite_request.discord_user_id

        # Check if request has expired
        if lite_request.is_expired():
            lite_request.mark_expired()
            session.commit()
            return False, None, "expired", "Validation request has expired", discord_user_id

        # Perform IP validation
        ip_valid, matched_node_uuid, ip_error = validate_ip_ownership(
            validator_id, client_ip, session
        )

        if ip_valid:
            # Mark as validated and update request
            lite_request.mark_validated(client_ip, matched_node_uuid)
            session.commit()
            logger.info(f"Successfully validated validator {validator_id} from IP {client_ip}")
            return True, matched_node_uuid, "validated", "Validator ownership successfully validated.", discord_user_id
        else:
            # Don't mark as failed - allow retries from different IPs
            error_msg = ip_error or "IP address does not match expected validator IPs."
            logger.warning(f"Validation failed for validator {validator_id} from IP {client_ip}: {error_msg}")
            return False, matched_node_uuid, "failed", f"Validator ownership validation failed: {error_msg}", discord_user_id

    except Exception as e:
        logger.error(f"Error processing validation request for {validator_id}: {e}")
        return False, None, "error", "Failed to process validation request", None


def get_user_validators(session: Session, discord_user_id: int) -> List[ValidatorLiteRequest]:
    """
    Get all validated validators for a Discord user.

    Args:
        session: Database session
        discord_user_id: Discord user ID

    Returns:
        List of validated ValidatorLiteRequest objects
    """
    try:
        logger.info(f"Getting validators for Discord user {discord_user_id}")

        user_validators = session.query(ValidatorLiteRequest).filter(
            ValidatorLiteRequest.discord_user_id == discord_user_id,
            ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
        ).all()

        logger.info(f"Found {len(user_validators)} validators for user {discord_user_id}")
        return user_validators

    except Exception as e:
        logger.error(f"Error getting user validators for {discord_user_id}: {e}")
        return []


def resolve_validator_selection(
    session: Session,
    discord_user_id: int,
    validator_address: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[List[Dict[str, Any]]], str]:
    """
    Resolve validator selection using the same logic as the info endpoint.

    Args:
        session: Database session
        discord_user_id: Discord user ID
        validator_address: Optional validator address

    Returns:
        Tuple of (success, selected_validator_address, validator_list, message)
        - If success=True and validator_list=None: Use selected_validator_address
        - If success=True and validator_list is not None: Return list to user
        - If success=False: Error occurred, message contains error
    """
    try:
        logger.info(f"Resolving validator selection for user {discord_user_id}, address: {validator_address}")

        # Get user's validators
        user_validators = get_user_validators(session, discord_user_id)
        validator_count = len(user_validators)

        # Handle case where no validator_address provided
        if not validator_address:
            if validator_count == 0:
                return False, None, None, "You must provide a validator address"
            elif validator_count == 1:
                # Use the single validator they have
                selected_address = user_validators[0].validator_id
                logger.info(f"Auto-selected single validator: {selected_address}")
                return True, selected_address, None, f"Using your validator: {selected_address}"
            else:
                # Return list of validators
                validator_list = [
                    {
                        "validator_id": v.validator_id,
                        "last_validated": v.updated_at
                    }
                    for v in user_validators
                ]
                return True, None, validator_list, "Multiple validators found. Please specify one."

        # validator_address was provided - check if user owns it
        user_owns_validator = any(v.validator_id == validator_address for v in user_validators)

        if not user_owns_validator:
            return False, None, None, f"You don't own validator {validator_address} or it hasn't been validated within 90 days."

        logger.info(f"User owns validator: {validator_address}")
        return True, validator_address, None, f"Using validator: {validator_address}"

    except Exception as e:
        logger.error(f"Error resolving validator selection: {e}")
        return False, None, None, "Failed to resolve validator selection"


def validate_rescan_authority(
    session: Session,
    discord_user_id: int,
    validator_address: str
) -> Tuple[bool, Optional[ValidatorLiteRequest], str]:
    """
    Validate that user has authority to rescan the specified validator.

    Args:
        session: Database session
        discord_user_id: Discord user ID
        validator_address: Validator address to check

    Returns:
        Tuple of (has_authority, validation_request, error_message)
    """
    try:
        logger.info(f"Validating rescan authority for user {discord_user_id}, validator {validator_address}")

        # Check 90-day validation authority
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        validation = session.query(ValidatorLiteRequest).filter(
            ValidatorLiteRequest.validator_id == validator_address,
            ValidatorLiteRequest.discord_user_id == discord_user_id,
            ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED,
            ValidatorLiteRequest.updated_at >= ninety_days_ago
        ).order_by(ValidatorLiteRequest.updated_at.desc()).first()

        if not validation:
            return False, None, "No valid validation found within 90 days."

        logger.info(f"Rescan authority validated for user {discord_user_id}, validator {validator_address}")
        return True, validation, "Authority validated"

    except Exception as e:
        logger.error(f"Error validating rescan authority: {e}")
        return False, None, "Failed to validate rescan authority"


def log_rescan_request(
    session: Session,
    validator_address: str,
    discord_user_id: int,
    node_uuid: str,
    lite_request_uuid: str,
    client_ip: str
) -> Optional[str]:
    """
    Log a rescan request to the database.

    Args:
        session: Database session
        validator_address: Validator address
        discord_user_id: Discord user ID
        node_uuid: Node UUID
        lite_request_uuid: Lite request UUID
        client_ip: Client IP address

    Returns:
        Rescan log UUID if successful, None if failed
    """
    try:
        logger.info(f"Logging rescan request for validator {validator_address} by user {discord_user_id}")

        rescan_log = RescanRequestLog(
            validator_id=validator_address,
            discord_user_id=discord_user_id,
            node_uuid=node_uuid,
            lite_request_uuid=lite_request_uuid,
            ip_address=client_ip
        )
        session.add(rescan_log)
        session.commit()
        session.refresh(rescan_log)

        logger.info(f"Rescan request logged: {rescan_log.uuid}")
        return str(rescan_log.uuid)

    except Exception as e:
        logger.error(f"Error logging rescan request: {e}")
        return None