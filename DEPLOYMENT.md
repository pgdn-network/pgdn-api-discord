# Ultra-Minimal Lite Validation API Deployment

## Required Environment Variables

### Essential Secrets (stored in `pgdn-lite-api-secrets`)

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@127.0.0.1:5432/depin` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `DISCORD_API_AUTH_TOKEN` | Discord bot authentication token | `your_discord_bot_token_here` |
| `DISCORD_NOTIFICATION_CHANNEL` | Discord admin notification webhook URL | `https://discord.com/api/webhooks/...` |

### Application Configuration (set as literal values)

| Variable | Value | Description |
|----------|-------|-------------|
| `DEBUG` | `"false"` | Disable debug mode in production |
| `ENVIRONMENT` | `"production"` | Environment identifier |
| `LOG_LEVEL` | `"INFO"` | Logging level |
| `ALLOWED_ORIGINS` | `"*"` | CORS origins (comma-separated) |
| `LITE_TOKEN_EXPIRY_MINUTES` | `"45"` | Token expiry time in minutes |
| `PORT` | `"8000"` | Application port |

## K8s Secret Creation

Create the required secrets in your cluster:

```bash
# Create the secret with required values
kubectl create secret generic pgdn-lite-api-secrets \
  --from-literal=DATABASE_URL="postgresql://user:pass@127.0.0.1:5432/depin" \
  --from-literal=REDIS_URL="redis://your-redis-host:6379" \
  --from-literal=DISCORD_API_AUTH_TOKEN="your_discord_bot_token" \
  --from-literal=DISCORD_NOTIFICATION_CHANNEL="https://discord.com/api/webhooks/your-webhook-url"
```

## Deployment

```bash
# Deploy the lite validation API
kubectl apply -f k8s-lite-validation-deployment.yaml

# Check deployment status
kubectl get pods -l app=pgdn-lite-validation-api

# Check logs
kubectl logs -l app=pgdn-lite-validation-api -f
```

## API Endpoints

Once deployed, the API will be available at:

- **Health Check:** `GET /health`
- **Public Validation:** `GET /api/v1/lite/public/validate/{validator_id}`
- **Private Endpoints (requires Discord bot auth):**
  - `POST /api/v1/lite/private/claim` - Claim existing validators
  - `POST /api/v1/lite/private/add` - Submit new validators for admin review
  - `GET /api/v1/lite/private/info/{validator_id}` - Get validator info
  - `POST /api/v1/lite/private/rescan/{validator_id}` - Request rescan
  - `POST /api/v1/lite/private/welcomed/{discord_user_id}` - Check welcome status
  - `GET /api/v1/lite/private/validators` - List user's validators

## Resource Requirements

**Minimal resource allocation:**
- **API Container:** 100m CPU, 64Mi memory (requests) | 500m CPU, 256Mi memory (limits)
- **Cloud SQL Proxy:** 10m CPU, 32Mi memory (requests) | 100m CPU, 64Mi memory (limits)

**Total cluster resources needed:** ~110m CPU, ~96Mi memory

## Differences from Full PGDN API

**Removed (not needed for lite validation):**
- JWT authentication and SECRET_KEY
- AI provider API keys (Anthropic, OpenAI)
- Email/SMTP configuration
- Blockchain configuration (ZkSync, SUI, etc.)
- DEPIN configuration
- GitHub PAT
- Twitter/X API keys
- PGDN reporter settings
- 50+ other environment variables

**Kept (essential for lite validation):**
- Database connection
- Redis caching
- Discord bot authentication
- Basic app configuration
- Health checks

This deployment is ~95% smaller in terms of configuration complexity compared to the full PGDN API deployment.