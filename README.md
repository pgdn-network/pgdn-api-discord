# PGDN API Discord

Ultra-minimal lite validation FastAPI application for Discord bot integration. This service provides secure Discord OAuth2 guild verification and validator management functionality for the PGDN network.

## Overview

This API service handles:
- **Discord OAuth2 Authentication** - Guild membership verification with secure state management
- **Validator Management** - Lite validation requests and ownership verification
- **Redis Caching** - High-performance caching for verification status and rate limiting
- **Database Integration** - PostgreSQL storage for persistent data
- **Security** - HMAC-signed tokens, rate limiting, and comprehensive input validation

## Dependencies

**⚠️ Required Companion Service**

This API requires the Discord bot service to function properly:
- **Discord Bot**: [pgdn-network/pgdn-discord](https://github.com/pgdn-network/pgdn-discord)

The Discord bot handles user interactions and communicates with this API for backend operations.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│  Discord Users  │◄──►│   PGDN Discord   │◄──►│ PGDN API Discord│
│                 │    │      Bot         │    │   (This Repo)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                         │
                                │                         │
                                ▼                         ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │                 │    │                 │
                       │ Discord OAuth2  │    │   PostgreSQL    │
                       │   & Webhooks    │    │   Database      │
                       │                 │    │                 │
                       └─────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │                 │
                                                │  Redis Cache    │
                                                │                 │
                                                └─────────────────┘
```

## Features

### 🔐 Security
- **OAuth2 Flow**: Secure Discord authentication with CSRF protection
- **HMAC State Tokens**: Cryptographically signed state tokens (10-minute expiry)
- **Rate Limiting**: Comprehensive rate limiting across all endpoints
- **Account Age Verification**: Minimum Discord account age requirements
- **Bearer Token Authentication**: Secure API access for bot communications

### 🚀 Performance
- **Redis Caching**: Fast verification status and rate limit tracking
- **Connection Pooling**: Optimized database connections
- **Minimal Footprint**: Lightweight Alpine-based Docker container

### 📊 Validation System
- **Validator Ownership**: DNS-based validation for node operators
- **Guild Verification**: Automated Discord server membership checks
- **Persistent Storage**: Long-term verification tracking
- **Audit Logging**: Comprehensive request and validation logging

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL database
- Redis instance
- Discord Application (OAuth2 credentials)

### Environment Setup

Create a `.env` file with required variables:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/pgdn

# Discord OAuth2 Configuration
OAUTH_CLIENT_ID=your_discord_app_client_id
OAUTH_CLIENT_SECRET=your_discord_app_client_secret
OAUTH_REDIRECT_URI=http://localhost:8000/api/v1/lite/public/discord/callback
STATE_SIGNING_KEY=your_32_character_signing_key

# Discord Integration
DISCORD_API_AUTH_TOKEN=your_bot_api_token
DISCORD_BOT_WEBHOOK_URL=http://localhost:8080/webhook/send-message
ALLOWED_GUILD_IDS=comma,separated,guild,ids

# Optional Configuration
DEBUG=False
ALLOWED_ORIGINS=*
VERIFY_SUCCESS_TTL_DAYS=90
MIN_ACCOUNT_AGE_DAYS=7
```

### Local Development

```bash
# Clone repository
git clone https://github.com/pgdn-network/pgdn-api-discord.git
cd pgdn-api-discord

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

The API will be available at `http://localhost:8000`

### Docker Deployment

```bash
# Build image
docker build -t pgdn-api-discord .

# Run container
docker run -p 8000:8000 --env-file .env pgdn-api-discord
```

### Kubernetes Deployment

This service is designed for Kubernetes deployment with network-level security:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgdn-api-discord
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pgdn-api-discord
  template:
    metadata:
      labels:
        app: pgdn-api-discord
    spec:
      containers:
      - name: api
        image: pgdn-api-discord:latest
        ports:
        - containerPort: 8000
        envFrom:
        - secretRef:
            name: pgdn-api-secrets
```

## API Endpoints

### Public Endpoints (No Authentication)
- `GET /` - API status and version
- `GET /health` - Health check
- `GET /api/v1/lite/public/discord/start` - Start OAuth2 flow
- `GET /api/v1/lite/public/discord/callback` - OAuth2 callback
- `GET /api/v1/lite/public/validate/{validator_id}` - Validator ownership validation

### Private Endpoints (Bot Authentication Required)
- `POST /api/v1/lite/private/claim` - Create validation request
- `GET /api/v1/lite/private/verify/{discord_user_id}` - Check verification status
- `GET /api/v1/lite/private/info` - Get validator information
- `GET/POST /api/v1/lite/private/rescan` - Request validator rescan
- `GET /api/v1/lite/private/validators` - List user's validators
- `POST /api/v1/lite/private/add` - Submit new validator for review

## Development

### Running Tests

```bash
pytest
```

### Code Quality

```bash
# Format code (if using black)
black .

# Lint code (if using ruff)
ruff check .
```

### Database Setup

The application auto-creates database tables on startup. For manual setup:

```bash
# Create database
createdb pgdn

# Tables are auto-created when the application starts
python main.py
```

## Security Considerations

This application implements defense-in-depth security:

1. **Network Isolation**: Designed for Kubernetes deployment with network policies
2. **Authentication**: Multiple layers of token-based authentication
3. **Input Validation**: Comprehensive request validation using Pydantic
4. **Rate Limiting**: Protection against abuse and DoS attacks
5. **Secrets Management**: All sensitive data via environment variables
6. **SQL Injection Protection**: Parameterized queries throughout

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `OAUTH_CLIENT_ID` | Yes | - | Discord application client ID |
| `OAUTH_CLIENT_SECRET` | Yes | - | Discord application client secret |
| `STATE_SIGNING_KEY` | Yes | - | HMAC signing key (32+ chars) |
| `DISCORD_API_AUTH_TOKEN` | Yes | - | Bot authentication token |
| `ALLOWED_GUILD_IDS` | Yes | - | Comma-separated Discord guild IDs |
| `DEBUG` | No | `False` | Enable debug mode |
| `ALLOWED_ORIGINS` | No | `*` | CORS allowed origins |
| `VERIFY_SUCCESS_TTL_DAYS` | No | `90` | Verification cache TTL |
| `MIN_ACCOUNT_AGE_DAYS` | No | `7` | Minimum Discord account age |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- **Issues**: [GitHub Issues](https://github.com/pgdn-network/pgdn-api-discord/issues)
- **Discussions**: [GitHub Discussions](https://github.com/pgdn-network/pgdn-api-discord/discussions)

## Related Repositories

- **Discord Bot**: [pgdn-network/pgdn-discord](https://github.com/pgdn-network/pgdn-discord) - Required companion service
- **PGDN Network**: [pgdn-network](https://github.com/pgdn-network) - Main organization