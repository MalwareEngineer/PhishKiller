"""Root API router aggregating all sub-routers."""

from fastapi import APIRouter

from phishkiller.api import actors, analysis, campaigns, feeds, health, indicators, kits

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(kits.router, prefix="/kits", tags=["kits"])
api_router.include_router(indicators.router, prefix="/indicators", tags=["indicators"])
api_router.include_router(actors.router, prefix="/actors", tags=["actors"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["feeds"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
