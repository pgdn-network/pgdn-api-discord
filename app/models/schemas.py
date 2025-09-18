"""
Pydantic schemas for lite validation API.
"""

from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import re


class ValidatorLiteRequest(BaseModel):
    """Request model for Discord validator lite requests."""
    validator_id: str = Field(..., min_length=1, max_length=255, description="Validator hostname (e.g., 'sui.test.net')")
    discord_user_id: int = Field(..., description="Discord user ID as integer")
    corp_email: Optional[EmailStr] = Field(None, description="Optional corporate email for results")

    @validator('validator_id')
    def validate_validator_id(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Validator ID cannot be empty')
        # Basic hostname validation - no consecutive dots, starts and ends with alphanumeric
        v = v.strip().lower()
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', v):
            raise ValueError('Validator ID must be a valid hostname')
        return v


class ValidatorLiteResponse(BaseModel):
    """Response model for validator lite request creation."""
    validator_id: str
    validation_url: str
    claim_token: Optional[str] = None
    dns_fallback: Optional[Dict[str, str]] = None
    expires_at: Optional[datetime] = None


class ValidatorLiteValidationResponse(BaseModel):
    """Response model for validator lite validation."""
    success: bool
    message: str
    validator_id: str
    status: str


class ValidatorNodeInfoResponse(BaseModel):
    """Response model for Discord slash command node info."""
    success: bool
    validator_address: str
    discord_user_id: int
    node_data: Optional[Dict[str, Any]] = None
    message: str
    last_validated: Optional[datetime] = None


class ValidatorRescanResponse(BaseModel):
    """Response model for Discord slash command rescan request."""
    success: bool
    validator_address: str
    discord_user_id: int
    message: str
    last_validated: Optional[datetime] = None


class UserWelcomedResponse(BaseModel):
    """Response model for Discord user welcome status check."""
    new: bool


class ValidatorInfo(BaseModel):
    """Individual validator information."""
    validator_id: str
    validator_address: Optional[str] = None
    status: str
    last_validated: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    nickname: Optional[str] = None
    trust_score: Optional[float] = None
    last_scan_status: Optional[str] = None


class ValidatorsListResponse(BaseModel):
    """Response model for validators list endpoint."""
    success: bool
    data: Dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "data": {
                    "validators": [
                        {
                            "validator_id": "prod.sui.infstones.io",
                            "validator_address": "0x123abc",
                            "status": "active",
                            "last_validated": "2024-01-15T10:30:00Z",
                            "expires_at": "2024-04-15T10:30:00Z",
                            "nickname": None,
                            "trust_score": 8.5,
                            "last_scan_status": "completed"
                        }
                    ],
                    "total_count": 1,
                    "primary_validator_id": "prod.sui.infstones.io"
                }
            }
        }


class ValidatorAddResponse(BaseModel):
    """Response model for validator add request endpoint."""
    success: bool
    data: Dict[str, Any]

    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "data": {
                    "validator_id": "mysten.prod.mainnet.dev",
                    "status": "submitted",
                    "message": "Validator submitted for review. You'll be notified when it's added to the system."
                }
            }
        }