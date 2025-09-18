"""
Ultra-minimal lite validation FastAPI app.
"""

import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Import our separated routers and cache
from app.routers.lite_validation import public_router, private_router
from app.services.redis_cache import get_redis_cache

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create FastAPI app
app = FastAPI(
    title="Lite Validation API",
    version="0.1.0",
    description="Minimal lite validation API for Discord bot integration"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Include separated public and private lite validation routers
app.include_router(public_router, prefix="/api/v1/lite/public", tags=["lite-validation-public"])
app.include_router(private_router, prefix="/api/v1/lite/private", tags=["lite-validation-private"])

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "0.1.0"}

# Application startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize Redis cache."""
    try:
        await get_redis_cache()
        logging.info("Redis cache initialized")
    except Exception as e:
        logging.error(f"Failed to initialize Redis: {e}")
        # Don't raise - allow app to start without Redis

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup Redis connection."""
    try:
        cache = await get_redis_cache()
        await cache.close()
        logging.info("Redis cache closed")
    except Exception as e:
        logging.error(f"Error closing Redis: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)