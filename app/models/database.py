"""
Complete database setup with all models for lite validation API.

This single file contains everything needed for database operations:
- SQLAlchemy Base and engine setup
- All database models inline
- Database session management
"""

import os
import logging
import uuid
from datetime import datetime
from enum import Enum
from contextlib import contextmanager
from typing import Optional, List

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime,
    ForeignKey, JSON, UUID, UniqueConstraint, Text, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)

# Database connection settings
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://simon@localhost:5432/depin")

# Create SQLAlchemy engine and session factory
engine = create_engine(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=3600
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ===== ENUMS =====

class OwnerType(str, Enum):
    """Node ownership types."""
    INDIVIDUAL = "individual"
    ORGANIZATION = "organization"
    UNKNOWN = "unknown"

class ClaimStatus(str, Enum):
    """Node claim status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class SimpleNodeState(str, Enum):
    """Simplified node states."""
    NEW = "new"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"

class DiscoveryStatus(str, Enum):
    """Node discovery status."""
    PENDING = "pending"
    DISCOVERED = "discovered"
    FAILED = "failed"

class ConnectivityStatus(str, Enum):
    """Node connectivity status."""
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"

class ValidatorLiteRequestStatus(str, Enum):
    """Validator lite request status."""
    ISSUED = "issued"
    VALIDATED = "validated"
    EXPIRED = "expired"
    FAILED = "failed"

# ===== MODELS =====

class Organization(Base):
    """Basic organization model."""
    __tablename__ = 'organizations'

    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

class Node(Base):
    """Node model for validators."""
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    organization_uuid = Column(UUID(as_uuid=True), ForeignKey('organizations.uuid'), nullable=False)
    name = Column(String(255))
    address = Column(String(255), nullable=False)  # hostname/address of the node
    status = Column(String(50), default='new')
    simple_state = Column(SQLEnum(SimpleNodeState), default=SimpleNodeState.NEW)
    validated = Column(Boolean, default=False)
    discovery_status = Column(SQLEnum(DiscoveryStatus), default=DiscoveryStatus.PENDING)
    connectivity_status = Column(SQLEnum(ConnectivityStatus), default=ConnectivityStatus.UNKNOWN)
    network = Column(String(100))
    node_type = Column(String(100))
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", foreign_keys=[organization_uuid])
    resolved_ips = relationship("NodeIp", back_populates="node", cascade="all, delete-orphan")

class NodeIp(Base):
    """Node IP addresses."""
    __tablename__ = 'node_ips'

    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, ForeignKey('nodes.id'), nullable=False)
    ip_address = Column(String(45), nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=func.now())

    # Relationships
    node = relationship("Node", back_populates="resolved_ips")

class ValidatorLiteRequest(Base):
    """Lite validation requests from Discord bot."""
    __tablename__ = 'validator_lite_requests'

    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    validator_id = Column(String(255), nullable=False)  # hostname/address to validate
    discord_user_id = Column(Integer, nullable=False)
    corp_email = Column(String(255))
    request_token = Column(String(255))  # claim token
    expires_at = Column(DateTime)
    status = Column(SQLEnum(ValidatorLiteRequestStatus), nullable=False, default=ValidatorLiteRequestStatus.ISSUED)
    validation_ip = Column(String(45))  # IP that was validated
    node_uuid = Column(UUID(as_uuid=True), ForeignKey('nodes.uuid'))  # matched node
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    def is_expired(self) -> bool:
        """Check if request has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def mark_validated(self, ip_address: str, node_uuid: str = None):
        """Mark request as validated."""
        self.status = ValidatorLiteRequestStatus.VALIDATED
        self.validation_ip = ip_address
        if node_uuid:
            self.node_uuid = node_uuid
        self.updated_at = datetime.utcnow()

    def mark_failed(self):
        """Mark request as failed."""
        self.status = ValidatorLiteRequestStatus.FAILED
        self.updated_at = datetime.utcnow()

    def mark_expired(self):
        """Mark request as expired."""
        self.status = ValidatorLiteRequestStatus.EXPIRED
        self.updated_at = datetime.utcnow()

class RescanRequestLog(Base):
    """Log of rescan requests for future notifications."""
    __tablename__ = 'rescan_request_logs'

    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4)
    validator_id = Column(String(255), nullable=False)
    discord_user_id = Column(Integer, nullable=False)
    node_uuid = Column(UUID(as_uuid=True), ForeignKey('nodes.uuid'))
    lite_request_uuid = Column(UUID(as_uuid=True), ForeignKey('validator_lite_requests.uuid'))
    ip_address = Column(String(45))
    created_at = Column(DateTime, nullable=False, default=func.now())

class NodeTimeseries(Base):
    """Node timeseries data for info display."""
    __tablename__ = 'node_timeseries'

    id = Column(Integer, primary_key=True)
    node_key = Column(String(100), nullable=False)  # Usually node UUID as string
    observed_ts = Column(DateTime, nullable=False)

    # Performance metrics
    tps = Column(String(20))
    tps_bucket = Column(String(50))
    tps_color = Column(String(20))
    tps_method = Column(String(50))
    tps_confidence = Column(String(20))
    cps = Column(String(20))
    cps_bucket = Column(String(50))
    cps_color = Column(String(20))

    # Uptime and availability
    uptime_status = Column(String(20))
    uptime_color = Column(String(20))
    uptime_sla_applicable = Column(Boolean)
    uptime_expected = Column(String(10))

    # Security metrics
    latest_score = Column(Integer)
    total_cves = Column(Integer)
    critical_cves = Column(Integer)
    high_severity_cves = Column(Integer)
    total_issues = Column(Integer)

    # Infrastructure details
    ssh_open = Column(Boolean)
    docker_open = Column(Boolean)
    docker_api_accessible = Column(Boolean)
    unexpected_ports = Column(JSON)
    unexpected_ports_color = Column(String(20))
    waf_detected = Column(Boolean)
    metrics_exposed = Column(Boolean)
    tls_enabled = Column(Boolean)
    web_server_detected = Column(Boolean)
    total_open_ports_count = Column(Integer)

    # RPC and connectivity
    rpc_status = Column(String(20))
    rpc_reachable = Column(Boolean)
    rpc_rate_limit_events = Column(Integer)
    rpc_methods_count = Column(Integer)
    grpc_available = Column(Boolean)
    websocket_available = Column(Boolean)
    open_ports_grpc = Column(JSON)
    open_grpc_ports = Column(JSON)

    # Blockchain specific
    protocol_version = Column(String(20))
    current_epoch = Column(Integer)
    checkpoint_height = Column(Integer)
    chain_identifier = Column(String(100))
    reference_gas_price = Column(String(50))
    validator_count = Column(Integer)
    total_stake = Column(String(50))

    # Performance and reliability
    response_time_ms = Column(String(20))
    data_completeness_pct = Column(String(10))
    rpc_success_rate_pct = Column(String(10))
    node_health_score = Column(String(10))
    extraction_error_count = Column(Integer)
    rate_limiting_active = Column(Boolean)

    # Network classification
    asn = Column(String(20))

    # Data quality and metadata
    has_tps = Column(Boolean)
    has_cps = Column(Boolean)
    has_uptime = Column(Boolean)
    missing_reason = Column(String(255))
    data_freshness_hours = Column(String(10))
    suppress_from_heatmap = Column(Boolean)
    hostname = Column(String(255))
    ip_or_host = Column(String(255))
    port = Column(Integer)
    edge = Column(Boolean)

# ===== DATABASE OPERATIONS =====

@contextmanager
def get_db_session():
    """Get database session context manager"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Unexpected error: {e}")
        raise
    finally:
        session.close()

def create_tables():
    """Create database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        raise

def init_database():
    """Initialize database"""
    create_tables()
    logger.info("Database initialized successfully")

# Simple validation function
def validate_node_address(address: str) -> tuple[bool, Optional[str]]:
    """Simple node address validation function."""
    if not address or len(address.strip()) == 0:
        return False, "Address cannot be empty"

    address = address.strip().lower()

    # Basic hostname/IP validation
    import re
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', address):
        return False, "Address must be a valid hostname or IP address"

    if len(address) > 255:
        return False, "Address too long"

    return True, None


def get_user_validators(session: Session, discord_user_id: int) -> dict:
    """Get all validators for a Discord user."""
    try:
        # Query validated requests to find user's validators
        validated_requests = session.query(ValidatorLiteRequest).filter(
            ValidatorLiteRequest.discord_user_id == discord_user_id,
            ValidatorLiteRequest.status == ValidatorLiteRequestStatus.VALIDATED
        ).all()

        validators = []
        primary_validator_id = None

        for req in validated_requests:
            # Get associated node if available
            node = None
            if req.node_uuid:
                node = session.query(Node).filter(Node.uuid == req.node_uuid).first()

            validator_info = {
                "validator_id": req.validator_id,
                "validator_address": node.ip_addresses[0].ip_address if node and node.ip_addresses else req.validation_ip,
                "status": "active" if req.status == ValidatorLiteRequestStatus.VALIDATED else "inactive",
                "last_validated": req.updated_at,
                "expires_at": req.expires_at,
                "nickname": None,  # Not stored in current schema
                "trust_score": node.trust_score if node and hasattr(node, 'trust_score') else None,
                "last_scan_status": "completed" if req.status == ValidatorLiteRequestStatus.VALIDATED else "pending"
            }
            validators.append(validator_info)

            # Set first validator as primary
            if primary_validator_id is None:
                primary_validator_id = req.validator_id

        return {
            "validators": validators,
            "total_count": len(validators),
            "primary_validator_id": primary_validator_id
        }

    except Exception as e:
        logger.error(f"Error fetching user validators: {e}")
        return {
            "validators": [],
            "total_count": 0,
            "primary_validator_id": None
        }