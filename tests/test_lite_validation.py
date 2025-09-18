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

def test_root_endpoint():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Lite Validation API"
    assert data["version"] == "0.1.0"
    assert data["status"] == "running"

def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "version": "0.1.0"}

def test_claim_validation_missing_auth():
    """Test validation claim without auth header."""
    response = client.post("/api/v1/lite/private/claim", json={
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

def test_add_validator_missing_auth():
    """Test add validator without auth header."""
    response = client.post("/api/v1/lite/private/add", json={
        "validator_id": "new.validator.com",
        "discord_user_id": 123456789
    })
    assert response.status_code == 401

def test_add_validator_missing_param():
    """Test add validator without required parameters."""
    response = client.post("/api/v1/lite/private/add", json={}, headers={
        "Authorization": "Bearer test_token"
    })
    assert response.status_code == 422  # Validation error for missing required parameters

def test_add_validator_invalid_url():
    """Test add validator with invalid URL format."""
    import os
    # Get the real token from environment for testing
    real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")
    response = client.post("/api/v1/lite/private/add", json={
        "validator_id": "asdfasdf",  # Invalid URL - no domain
        "discord_user_id": 123456789
    }, headers={
        "Authorization": f"Bearer {real_token}"
    })
    assert response.status_code == 400
    data = response.json()
    assert "Invalid hostname/domain format" in data["detail"]

def test_add_validator_empty_url():
    """Test add validator with empty URL (Pydantic validation should catch this)."""
    import os
    real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")
    response = client.post("/api/v1/lite/private/add", json={
        "validator_id": "",  # Empty URL
        "discord_user_id": 123456789
    }, headers={
        "Authorization": f"Bearer {real_token}"
    })
    assert response.status_code == 422  # Pydantic validation error
    data = response.json()
    assert "detail" in data

def test_add_validator_no_dot_url():
    """Test add validator with no dot in URL."""
    import os
    real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")
    response = client.post("/api/v1/lite/private/add", json={
        "validator_id": "localhost",  # No dot in hostname
        "discord_user_id": 123456789
    }, headers={
        "Authorization": f"Bearer {real_token}"
    })
    assert response.status_code == 400
    data = response.json()
    assert "Invalid hostname/domain format" in data["detail"]

def test_add_validator_valid_url_format():
    """Test add validator with valid URL format (will fail auth but URL validation should pass)."""
    response = client.post("/api/v1/lite/private/add", json={
        "validator_id": "validator.example.com",  # Valid URL format
        "discord_user_id": 123456789
    }, headers={
        "Authorization": "Bearer invalid_token"
    })
    # Should fail with 401 (invalid token) not 400 (invalid URL format)
    assert response.status_code == 401

if __name__ == "__main__":
    pytest.main([__file__])