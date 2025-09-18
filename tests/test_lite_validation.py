"""
Simple tests for lite validation API.
"""

import pytest
import sys
import os

# Add the parent directory to the path so we can import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "version": "0.1.0"}

def test_request_validation_missing_auth():
    """Test validation request without auth header."""
    response = client.post("/api/v1/lite/private/request", json={
        "validator_id": "test.validator.com",
        "discord_user_id": 123456789
    })
    assert response.status_code == 401

def test_validate_missing_request():
    """Test validation without existing request (public endpoint)."""
    response = client.get("/api/v1/lite/public/validate/nonexistent.validator.com")
    assert response.status_code == 404

def test_info_missing_auth():
    """Test info request without auth header."""
    response = client.get("/api/v1/lite/private/info/test.validator.com?discord_user_id=123")
    assert response.status_code == 401

def test_rescan_missing_auth():
    """Test rescan request without auth header."""
    response = client.post("/api/v1/lite/private/rescan/test.validator.com?discord_user_id=123")
    assert response.status_code == 401

def test_welcomed_missing_auth():
    """Test welcomed check without auth header."""
    response = client.post("/api/v1/lite/private/welcomed/123456789")
    assert response.status_code == 401

def test_validators_missing_auth():
    """Test validators list without auth header."""
    response = client.get("/api/v1/lite/private/validators?discord_user_id=123456789")
    assert response.status_code == 401

def test_validators_missing_param():
    """Test validators list without discord_user_id parameter."""
    response = client.get("/api/v1/lite/private/validators", headers={
        "Authorization": "Bearer test_token"
    })
    assert response.status_code == 422  # Validation error for missing required parameter

if __name__ == "__main__":
    pytest.main([__file__])