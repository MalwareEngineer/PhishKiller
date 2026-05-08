"""Root API router aggregating all sub-routers."""

from fastapi import APIRouter

from darla.api import (
    actors,
    analysis,
    campaigns,
    diff,
    families,
    health,
    indicators,
    investigations,
    kits,
    monitored_domains,
    phishmatch,
    victims,
    yara,
)

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(kits.router, prefix="/kits", tags=["kits"])
api_router.include_router(investigations.router, prefix="/investigations", tags=["investigations"])
api_router.include_router(indicators.router, prefix="/indicators", tags=["indicators"])
api_router.include_router(actors.router, prefix="/actors", tags=["actors"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
api_router.include_router(families.router, prefix="/families", tags=["families"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(diff.router, prefix="/diff", tags=["diff"])
api_router.include_router(yara.router, prefix="/yara", tags=["yara"])
api_router.include_router(phishmatch.router, prefix="/phishmatch", tags=["phishmatch"])
api_router.include_router(victims.router, prefix="/victims", tags=["phishprint"])
api_router.include_router(
    monitored_domains.router,
    prefix="/monitored-domains", tags=["phishprint"],
)
