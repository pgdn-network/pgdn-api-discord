"""
Tests for validator service module.

Tests the business logic for validator validation separated from router concerns.
"""

import pytest
import socket
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import Session

from app.services.validator_service import (
    resolve_validator_hostname,
    check_validator_exists_and_active,
    check_user_already_has_validator,
    validate_validator_for_claim
)
from app.models.database import Node, ValidatorLiteRequest, ValidatorLiteRequestStatus


class TestResolveValidatorHostname:
    """Test DNS resolution functionality."""

    @patch('socket.gethostbyname')
    def test_successful_dns_resolution(self, mock_gethostbyname):
        """Test successful DNS resolution."""
        mock_gethostbyname.return_value = "192.168.1.100"

        success, resolved_ip, error = resolve_validator_hostname("example.com")

        assert success is True
        assert resolved_ip == "192.168.1.100"
        assert error is None
        mock_gethostbyname.assert_called_once_with("example.com")

    @patch('socket.gethostbyname')
    def test_dns_resolution_failure(self, mock_gethostbyname):
        """Test DNS resolution failure."""
        mock_gethostbyname.side_effect = socket.gaierror("Name resolution failed")

        success, resolved_ip, error = resolve_validator_hostname("nonexistent.example.com")

        assert success is False
        assert resolved_ip is None
        assert "DNS resolution failed" in error

    @patch('socket.gethostbyname')
    def test_dns_resolution_with_protocol_prefix(self, mock_gethostbyname):
        """Test DNS resolution strips protocol prefix."""
        mock_gethostbyname.return_value = "192.168.1.100"

        success, resolved_ip, error = resolve_validator_hostname("https://example.com")

        assert success is True
        assert resolved_ip == "192.168.1.100"
        mock_gethostbyname.assert_called_once_with("example.com")

    @patch('socket.gethostbyname')
    def test_dns_resolution_with_port(self, mock_gethostbyname):
        """Test DNS resolution strips port number."""
        mock_gethostbyname.return_value = "192.168.1.100"

        success, resolved_ip, error = resolve_validator_hostname("example.com:8080")

        assert success is True
        assert resolved_ip == "192.168.1.100"
        mock_gethostbyname.assert_called_once_with("example.com")

    @patch('socket.gethostbyname')
    def test_dns_resolution_with_path(self, mock_gethostbyname):
        """Test DNS resolution strips path."""
        mock_gethostbyname.return_value = "192.168.1.100"

        success, resolved_ip, error = resolve_validator_hostname("example.com/api/v1")

        assert success is True
        assert resolved_ip == "192.168.1.100"
        mock_gethostbyname.assert_called_once_with("example.com")

    @patch('socket.gethostbyname')
    def test_dns_resolution_unexpected_error(self, mock_gethostbyname):
        """Test DNS resolution handles unexpected errors."""
        mock_gethostbyname.side_effect = Exception("Unexpected error")

        success, resolved_ip, error = resolve_validator_hostname("example.com")

        assert success is False
        assert resolved_ip is None
        assert "Unexpected error during DNS resolution" in error


class TestCheckValidatorExistsAndActive:
    """Test validator existence and active status checks."""

    def test_validator_exists_and_active(self):
        """Test validator exists and is active."""
        # Mock session and node
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()
        mock_node.active = True
        mock_node.address = "validator.example.com"
        mock_session.query.return_value.filter.return_value.first.return_value = mock_node

        exists, node, error = check_validator_exists_and_active(mock_session, "validator.example.com")

        assert exists is True
        assert node == mock_node
        assert error is None

    def test_validator_not_found(self):
        """Test validator does not exist."""
        mock_session = MagicMock(spec=Session)
        mock_session.query.return_value.filter.return_value.first.return_value = None

        exists, node, error = check_validator_exists_and_active(mock_session, "nonexistent.validator.com")

        assert exists is False
        assert node is None
        assert "Validator not found in system" in error

    def test_validator_exists_but_inactive(self):
        """Test validator exists but is not active."""
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()
        mock_node.active = False
        mock_node.address = "inactive.validator.com"
        mock_session.query.return_value.filter.return_value.first.return_value = mock_node

        exists, node, error = check_validator_exists_and_active(mock_session, "inactive.validator.com")

        assert exists is False
        assert node == mock_node
        assert "Validator exists but is not active" in error

    def test_database_error(self):
        """Test database error during validator check."""
        mock_session = MagicMock(spec=Session)
        mock_session.query.side_effect = Exception("Database connection failed")

        exists, node, error = check_validator_exists_and_active(mock_session, "validator.example.com")

        assert exists is False
        assert node is None
        assert "Database error checking validator" in error


class TestCheckUserAlreadyHasValidator:
    """Test checking if user already has validator."""

    def test_user_does_not_have_validator(self):
        """Test user does not have this validator."""
        mock_session = MagicMock(spec=Session)
        mock_session.query.return_value.filter.return_value.first.return_value = None

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is False
        assert error is None

    def test_user_has_validated_validator(self):
        """Test user already has validated request for this validator."""
        mock_session = MagicMock(spec=Session)
        mock_request = MagicMock()
        mock_request.status = ValidatorLiteRequestStatus.VALIDATED
        mock_session.query.return_value.filter.return_value.first.return_value = mock_request

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is True
        assert "already has validated request" in error

    def test_user_has_pending_validator(self):
        """Test user already has pending request for this validator."""
        mock_session = MagicMock(spec=Session)
        mock_request = MagicMock()
        mock_request.status = ValidatorLiteRequestStatus.ISSUED
        mock_session.query.return_value.filter.return_value.first.return_value = mock_request

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is True
        assert "already has pending request" in error

    def test_user_has_failed_validator_allows_new(self):
        """Test user has failed request, which allows new request."""
        mock_session = MagicMock(spec=Session)
        mock_request = MagicMock()
        mock_request.status = ValidatorLiteRequestStatus.FAILED
        mock_session.query.return_value.filter.return_value.first.return_value = mock_request

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is False
        assert error is None

    def test_user_has_expired_validator_allows_new(self):
        """Test user has expired request, which allows new request."""
        mock_session = MagicMock(spec=Session)
        mock_request = MagicMock()
        mock_request.status = ValidatorLiteRequestStatus.EXPIRED
        mock_session.query.return_value.filter.return_value.first.return_value = mock_request

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is False
        assert error is None

    def test_database_error_errs_on_caution(self):
        """Test database error returns True to err on side of caution."""
        mock_session = MagicMock(spec=Session)
        mock_session.query.side_effect = Exception("Database connection failed")

        user_has, error = check_user_already_has_validator(mock_session, 123456789, "validator.example.com")

        assert user_has is True
        assert "Database error checking user validator relationship" in error


class TestValidateValidatorForClaim:
    """Test complete validator validation logic."""

    @patch('app.services.validator_service.resolve_validator_hostname')
    @patch('app.services.validator_service.check_validator_exists_and_active')
    @patch('app.services.validator_service.check_user_already_has_validator')
    def test_successful_validation(self, mock_check_user, mock_check_validator, mock_resolve_dns):
        """Test successful complete validation."""
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()

        # Mock all checks to pass
        mock_check_validator.return_value = (True, mock_node, None)
        mock_resolve_dns.return_value = (True, "192.168.1.100", None)
        mock_check_user.return_value = (False, None)

        is_valid, node, resolved_ip, error = validate_validator_for_claim(
            mock_session, "validator.example.com", 123456789
        )

        assert is_valid is True
        assert node == mock_node
        assert resolved_ip == "192.168.1.100"
        assert error is None

    @patch('app.services.validator_service.resolve_validator_hostname')
    @patch('app.services.validator_service.check_validator_exists_and_active')
    @patch('app.services.validator_service.check_user_already_has_validator')
    def test_validator_not_found(self, mock_check_user, mock_check_validator, mock_resolve_dns):
        """Test validation fails when validator not found."""
        mock_session = MagicMock(spec=Session)

        mock_check_validator.return_value = (False, None, "Validator not found in system")
        # Other mocks shouldn't be called

        is_valid, node, resolved_ip, error = validate_validator_for_claim(
            mock_session, "nonexistent.validator.com", 123456789
        )

        assert is_valid is False
        assert node is None
        assert resolved_ip is None
        assert "Validator not found in system" in error

        # DNS and user checks should not be called if validator doesn't exist
        mock_resolve_dns.assert_not_called()
        mock_check_user.assert_not_called()

    @patch('app.services.validator_service.resolve_validator_hostname')
    @patch('app.services.validator_service.check_validator_exists_and_active')
    @patch('app.services.validator_service.check_user_already_has_validator')
    def test_dns_resolution_fails(self, mock_check_user, mock_check_validator, mock_resolve_dns):
        """Test validation fails when DNS resolution fails."""
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()

        mock_check_validator.return_value = (True, mock_node, None)
        mock_resolve_dns.return_value = (False, None, "DNS resolution failed")

        is_valid, node, resolved_ip, error = validate_validator_for_claim(
            mock_session, "validator.example.com", 123456789
        )

        assert is_valid is False
        assert node == mock_node
        assert resolved_ip is None
        assert "DNS resolution failed" in error

        # User check should not be called if DNS fails
        mock_check_user.assert_not_called()

    @patch('app.services.validator_service.resolve_validator_hostname')
    @patch('app.services.validator_service.check_validator_exists_and_active')
    @patch('app.services.validator_service.check_user_already_has_validator')
    def test_user_already_has_validator(self, mock_check_user, mock_check_validator, mock_resolve_dns):
        """Test validation fails when user already has validator."""
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()

        mock_check_validator.return_value = (True, mock_node, None)
        mock_resolve_dns.return_value = (True, "192.168.1.100", None)
        mock_check_user.return_value = (True, "User already has validated request")

        is_valid, node, resolved_ip, error = validate_validator_for_claim(
            mock_session, "validator.example.com", 123456789
        )

        assert is_valid is False
        assert node == mock_node
        assert resolved_ip == "192.168.1.100"
        assert "User already has validated request" in error

    @patch('app.services.validator_service.resolve_validator_hostname')
    @patch('app.services.validator_service.check_validator_exists_and_active')
    @patch('app.services.validator_service.check_user_already_has_validator')
    def test_validator_inactive(self, mock_check_user, mock_check_validator, mock_resolve_dns):
        """Test validation fails when validator is inactive."""
        mock_session = MagicMock(spec=Session)
        mock_node = MagicMock()

        mock_check_validator.return_value = (False, mock_node, "Validator exists but is not active")

        is_valid, node, resolved_ip, error = validate_validator_for_claim(
            mock_session, "inactive.validator.com", 123456789
        )

        assert is_valid is False
        assert node == mock_node
        assert resolved_ip is None
        assert "Validator exists but is not active" in error

        # DNS and user checks should not be called if validator is inactive
        mock_resolve_dns.assert_not_called()
        mock_check_user.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])