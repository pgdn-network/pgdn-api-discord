# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Database Setup
```bash
# The application will auto-create tables on startup, but you may need to create the database first
createdb depin

# Run the application to auto-create tables
python main.py
```

### Running the Application
```bash
# Activate virtual environment BEFORE running commands
source myenv/bin/activate

# Run the FastAPI application locally
python main.py
# OR
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Build and run with Docker
docker build --secret id=gh_pat,src=path/to/your/github_pat.txt -t pgdn-api .
docker run -p 8000:8000 --env-file .env pgdn-api
```

### Testing and Code Quality
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_interventions.py

# Run tests with specific marker
pytest -m "not slow"        # Skip slow tests
pytest -m auth             # Run only auth tests
pytest -m integration     # Run only integration tests
pytest -m fuzzing          # Run fuzzing/edge case tests

# Run tests with coverage
pytest --cov=. --cov-report=html

# Code formatting and linting (add these tools as needed)
# pip install ruff black
# ruff check .
# black .
```

### Database Operations
```bash
# Connect to database (local development)
psql -U username -d depin

# DATABASE_URLs (configure in .env):
# Local: postgresql://username:password@localhost:5432/depin
# Docker: postgresql://depin_user:secure_password_change_me@db:5432/depin
```

## Architecture Overview

### Core Application Flow
1. **User Registration/Auth** → Creates Organization → Assigns Roles
2. **Node Discovery** → Validates targets → Creates Node records
3. **Scanning Workflow** → PGDN scanner integration for security assessment
4. **WebSocket Integration** → Real-time notifications via pgdn-ws
5. **Background Processing** → Redis pub/sub for async operations

### Service Architecture

#### Core Services
- **models/**: Business logic and database models
  - `models.py`: SQLAlchemy ORM models for data persistence
  - `database.py`: PostgreSQL connection and session management
  - `schemas.py`: Pydantic validation models for API requests/responses
  - `auth.py`: JWT tokens and authentication logic

#### Application Services (services/)
- **redis_service.py**: Redis connection management for pub/sub
- **redis_pubsub_listener.py**: Real-time message handling
- **redis_job_publisher.py**: Job publishing for background tasks
- **websocket_heartbeat_service.py**: WebSocket connection health monitoring

#### API Routers (routers/)
- **auth.py**: Authentication endpoints (login, register, refresh)
- **users.py**: User management endpoints
- **organizations.py**: Organization CRUD operations
- **nodes.py**: Node discovery and management
- **scan.py**: Security scanning integration with PGDN
- **reporting.py**: Scan result reporting and analysis
- **public_nodes.py**: Public API endpoints for node data
- **security.py**: Security-related endpoints

### PGDN Framework Integration
The application integrates with private PGDN packages for security scanning:
- **Scanner**: `from pgdn.scanner import Scanner, Config`
- **Discovery**: `from pgdn_discovery import ProtocolDiscovery`
- **Reporter**: `from pgdn_reporter import create_reporter`
- **Scoring**: `from pgdn_scorer import create_scorer`
- **CVE Analysis**: `from pgdn_cve import CVEAnalyzer`
- **WebSocket**: `from pgdn_ws import create_websocket_router`
- **Publisher**: `from pgdn_publisher import publish_results`
- **Config**: Loaded from `config.json` for scanner configuration

### Security Architecture
- **Middleware Stack**: SecurityMiddleware → RequestValidationMiddleware → CORS
- **Authentication**: JWT (30min access, 7day refresh) + OAuth2 password flow
- **Password Security**: bcrypt(14 rounds) + HaveIBeenPwned breach check
- **Rate Limiting**: Configurable per endpoint (e.g., 5 registrations/hour)
- **Audit Trail**: All security events logged to audit_logs table

### Database Schema
The application uses PostgreSQL with SQLAlchemy ORM. Key relationships:
- Users belong to Organizations via UserOrganization mapping
- Organizations contain Nodes for scanning
- Nodes generate scan results and reports
- Real-time updates via Redis pub/sub system

## Development Best Practices

### Testing Approach
- Write tests FIRST following Red-Green TDD
- Use pytest fixtures in `tests/conftest.py`
- Mock external services (PGDN tools, APIs)
- Test markers available: `slow`, `integration`, `auth`, `fuzzing`

### API Development
- All endpoints under `/api/v1` prefix
- Use Pydantic schemas for request/response validation
- Implement authentication via `deps.get_current_user`
- Follow existing router patterns in `routers/` directory

### Error Handling
- Use proper HTTP status codes
- Provide descriptive error messages
- Log errors appropriately for debugging

### Code Quality
- Follow existing code patterns and conventions
- Use type hints where possible
- Keep functions focused and testable

## Common Development Tasks

### Creating New API Endpoint
1. Add router in `routers/` directory following existing patterns
2. Include router in `main.py` imports and `app.include_router()`
3. Add Pydantic schemas in `models/schemas.py` for request/response validation
4. Implement authentication via `deps.get_current_user` for protected endpoints
5. Add tests in `tests/test_routes_*.py`

### Adding New Database Models
1. Define model in `models/models.py` using SQLAlchemy
2. Update `models/schemas.py` with corresponding Pydantic models
3. Add any new database operations to appropriate service modules
4. Write tests for new functionality

### Integrating PGDN Services
1. Import required PGDN packages (scanner, reporter, etc.)
2. Follow existing patterns in `routers/scan.py` for integration
3. Handle results via Redis pub/sub system for real-time updates
4. Mock PGDN services in tests

## Discord OAuth2 Guild Verification

The application now includes Discord OAuth2 guild verification endpoints under `/api/v1/lite/public/discord/`:

### Endpoints
- `GET /api/v1/lite/public/discord/start?state=<state>` - Start OAuth2 flow (public, no auth required)
- `GET /api/v1/lite/public/discord/callback?code=...&state=...` - Handle OAuth2 callback (public, no auth required)

### Flow Overview
1. Discord bot generates state token using HMAC-signed format: `user_id:timestamp:mac`
2. Bot calls `/start` endpoint with state parameter
3. User is redirected to Discord OAuth2 authorization
4. Discord redirects back to `/callback` with authorization code
5. System exchanges code for token, fetches user's guilds, validates membership
6. Results cached in Redis and persisted in database

### Security Features
- **State Validation**: HMAC-signed state tokens prevent CSRF and user ID spoofing
- **10-minute Expiry**: State tokens expire after 10 minutes
- **Constant-time Comparison**: HMAC validation uses constant-time comparison
- **Base64url Encoding**: URL-safe encoding for state tokens

### Caching Strategy
- **Success**: Redis key `discord.verified:{user_id}` = "1" with 7-day TTL
- **Failure**: Redis key `discord.verified:{user_id}` = "0" with 10-minute TTL (negative cache)
- **Database**: Persistent record with verification status and expiration

### Optional Features
- **Bot DM**: Sends success DM when `BOT_TOKEN` is configured
- **Admin Notifications**: Can be integrated with existing notification system

## Environment Variables

### Required
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: JWT signing key (32+ chars)

### Optional
- `DEBUG`: Enable debug mode (default: False)
- `ENVIRONMENT`: development/staging/production
- `ALLOWED_ORIGINS`: CORS origins (comma-separated, default: *)
- `LOG_LEVEL`: Logging level (default: INFO)
- `INTERNAL_API_KEY`: Service-to-service authentication key
- `AI_PROVIDER_REPORTING`: AI provider for reporting (openai/anthropic)
- `ANTHROPIC_API_KEY`: Anthropic API key for AI analysis
- `OPENAI_API_KEY`: OpenAI API key for AI analysis

### Discord OAuth2 Variables
- `OAUTH_CLIENT_ID`: Discord OAuth2 application client ID
- `OAUTH_CLIENT_SECRET`: Discord OAuth2 application client secret
- `OAUTH_REDIRECT_URI`: OAuth2 redirect URI (must match Discord application settings)
- `STATE_SIGNING_KEY`: HMAC signing key (32+ characters for security)
- `ALLOWED_GUILD_IDS`: Comma-separated list of Discord guild IDs to verify membership
- `VERIFY_SUCCESS_TTL_DAYS`: Success verification TTL in days (default: 7)
- `VERIFY_FAIL_TTL_MINUTES`: Failure verification TTL in minutes (default: 10)
- `MIN_ACCOUNT_AGE_DAYS`: Minimum Discord account age in days (default: 7)
- `BOT_TOKEN`: Discord bot token for sending success DMs (optional)
- `OAUTH_BASE`: Discord API base URL (default: https://discord.com/api)
- `ALLOWED_TEST_USER_IDS`: Comma-separated list of Discord user IDs that bypass all verification checks for testing (optional)

## Docker Build Requirements

When building the Docker image, you need a GitHub Personal Access Token (PAT) to access private PGDN repositories:

```bash
# Create a file with your GitHub PAT
echo "your_github_pat_here" > github_pat.txt

# Build with the secret
docker build --secret id=gh_pat,src=github_pat.txt -t pgdn-api .

# Remove the PAT file for security
rm github_pat.txt
```

## Cursor Rules Integration
The `.cursor/rules/pgdn_dev.mdc` file provides additional FastAPI-specific guidance for Cursor users.

## Development Workflow

### Branch and Pull Request Strategy
- All new features, fixes, bugs etc should be opened in a separate branch
- Create pull requests for review before merging
- Do not work directly on the main branch

### Development Practices
- Do not use dynamic imports in Python
- Do not nest exception blocks
- Follow existing patterns and conventions
- Write tests for new functionality