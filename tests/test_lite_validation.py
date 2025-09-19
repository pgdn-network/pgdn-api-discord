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

def test_feedback_missing_auth():
    """Test feedback submission without auth header."""
    response = client.post("/api/v1/lite/private/feedback", json={
        "discord_user_id": 123456789,
        "message": "This is test feedback"
    })
    assert response.status_code == 401

def test_feedback_missing_param():
    """Test feedback submission without required parameters."""
    response = client.post("/api/v1/lite/private/feedback", json={}, headers={
        "Authorization": "Bearer test_token"
    })
    assert response.status_code == 422  # Validation error for missing required parameters

def test_feedback_empty_message():
    """Test feedback submission with empty message."""
    import os
    real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")
    response = client.post("/api/v1/lite/private/feedback", json={
        "discord_user_id": 123456789,
        "message": ""  # Empty message
    }, headers={
        "Authorization": f"Bearer {real_token}"
    })
    assert response.status_code == 422  # Pydantic validation error
    data = response.json()
    assert "detail" in data

def test_feedback_message_too_long():
    """Test feedback submission with message too long."""
    import os
    real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")
    long_message = "x" * 1001  # Over 1000 character limit
    response = client.post("/api/v1/lite/private/feedback", json={
        "discord_user_id": 123456789,
        "message": long_message
    }, headers={
        "Authorization": f"Bearer {real_token}"
    })
    assert response.status_code == 422  # Pydantic validation error
    data = response.json()
    assert "detail" in data

def test_feedback_valid_format():
    """Test feedback submission with valid format (will fail auth but format validation should pass)."""
    response = client.post("/api/v1/lite/private/feedback", json={
        "discord_user_id": 123456789,
        "message": "This is valid feedback message"
    }, headers={
        "Authorization": "Bearer invalid_token"
    })
    # Should fail with 401 (invalid token) not 422 (invalid format)
    assert response.status_code == 401


class TestRefactoredClaimValidation:
    """Test the refactored claim validation endpoint."""

    def test_claim_validation_with_mocked_service(self):
        """Test claim validation using service layer with mocking."""
        import os
        from unittest.mock import patch, AsyncMock

        real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")

        # Mock the service layer validation
        with patch('app.services.validator_service.validate_validator_for_claim') as mock_validate:
            # Mock successful validation
            mock_node = type('MockNode', (), {'uuid': 'test-uuid'})()
            mock_validate.return_value = (True, mock_node, "192.168.1.100", None)

            # Mock Redis cache with async methods
            with patch('app.routers.lite_validation.get_lite_validation_cache') as mock_cache:
                mock_cache_instance = mock_cache.return_value
                mock_cache_instance.has_pending_request = AsyncMock(return_value=False)
                mock_cache_instance.set_pending_request = AsyncMock(return_value=None)

                response = client.post("/api/v1/lite/private/claim", json={
                    "validator_id": "validator.example.com",
                    "discord_user_id": 123456789
                }, headers={
                    "Authorization": f"Bearer {real_token}"
                })

                # Should succeed and create validation request
                assert response.status_code == 200
                data = response.json()
                assert data["validator_id"] == "validator.example.com"
                assert "validation_url" in data

    def test_claim_validation_validator_not_found(self):
        """Test claim validation when validator not found."""
        import os
        from unittest.mock import patch, AsyncMock

        real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")

        with patch('app.services.validator_service.validate_validator_for_claim') as mock_validate:
            # Mock validator not found
            mock_validate.return_value = (False, None, None, "Validator not found in system: nonexistent.validator.com")

            with patch('app.routers.lite_validation.get_lite_validation_cache') as mock_cache:
                mock_cache_instance = mock_cache.return_value
                mock_cache_instance.has_pending_request = AsyncMock(return_value=False)

                response = client.post("/api/v1/lite/private/claim", json={
                    "validator_id": "nonexistent.validator.com",
                    "discord_user_id": 123456789
                }, headers={
                    "Authorization": f"Bearer {real_token}"
                })

                assert response.status_code == 404
                data = response.json()
                assert "not found" in data["detail"].lower()

    def test_claim_validation_user_already_has_validator(self):
        """Test claim validation when user already has this validator."""
        import os
        from unittest.mock import patch, AsyncMock

        real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")

        with patch('app.services.validator_service.validate_validator_for_claim') as mock_validate:
            # Mock user already has validator
            mock_node = type('MockNode', (), {'uuid': 'test-uuid'})()
            mock_validate.return_value = (False, mock_node, "192.168.1.100", "User 123456789 already has validated request for validator.example.com")

            with patch('app.routers.lite_validation.get_lite_validation_cache') as mock_cache:
                mock_cache_instance = mock_cache.return_value
                mock_cache_instance.has_pending_request = AsyncMock(return_value=False)

                response = client.post("/api/v1/lite/private/claim", json={
                    "validator_id": "validator.example.com",
                    "discord_user_id": 123456789
                }, headers={
                    "Authorization": f"Bearer {real_token}"
                })

                assert response.status_code == 409
                data = response.json()
                assert "already" in data["detail"].lower()

    def test_claim_validation_dns_failure(self):
        """Test claim validation when DNS resolution fails."""
        import os
        from unittest.mock import patch, AsyncMock

        real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")

        with patch('app.services.validator_service.validate_validator_for_claim') as mock_validate:
            # Mock DNS failure
            mock_node = type('MockNode', (), {'uuid': 'test-uuid'})()
            mock_validate.return_value = (False, mock_node, None, "DNS resolution failed for validator.example.com: Name resolution failed")

            with patch('app.routers.lite_validation.get_lite_validation_cache') as mock_cache:
                mock_cache_instance = mock_cache.return_value
                mock_cache_instance.has_pending_request = AsyncMock(return_value=False)

                response = client.post("/api/v1/lite/private/claim", json={
                    "validator_id": "validator.example.com",
                    "discord_user_id": 123456789
                }, headers={
                    "Authorization": f"Bearer {real_token}"
                })

                assert response.status_code == 400
                data = response.json()
                assert "dns resolution failed" in data["detail"].lower()

    def test_claim_validation_validator_inactive(self):
        """Test claim validation when validator exists but is inactive."""
        import os
        from unittest.mock import patch, AsyncMock

        real_token = os.getenv("DISCORD_API_AUTH_TOKEN", "cpWGkrKD21qHV2PZUHfB_vqMsO7X0y-bEAdcuz2SIb8")

        with patch('app.services.validator_service.validate_validator_for_claim') as mock_validate:
            # Mock inactive validator
            mock_node = type('MockNode', (), {'uuid': 'test-uuid', 'active': False})()
            mock_validate.return_value = (False, mock_node, None, "Validator exists but is not active: inactive.validator.com")

            with patch('app.routers.lite_validation.get_lite_validation_cache') as mock_cache:
                mock_cache_instance = mock_cache.return_value
                mock_cache_instance.has_pending_request = AsyncMock(return_value=False)

                response = client.post("/api/v1/lite/private/claim", json={
                    "validator_id": "inactive.validator.com",
                    "discord_user_id": 123456789
                }, headers={
                    "Authorization": f"Bearer {real_token}"
                })

                assert response.status_code == 400
                data = response.json()
                assert "not active" in data["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__])