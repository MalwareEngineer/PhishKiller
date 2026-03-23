"""All models imported here for Alembic autogeneration to detect them."""

from phishkiller.models.actor import Actor
from phishkiller.models.analysis_result import AnalysisResult, AnalysisType
from phishkiller.models.associations import campaign_actors, campaign_kits
from phishkiller.models.base import Base
from phishkiller.models.campaign import Campaign
from phishkiller.models.indicator import Indicator, IndicatorType
from phishkiller.models.investigation import Investigation, InvestigationStatus
from phishkiller.models.kit import Kit, KitStatus

__all__ = [
    "AnalysisResult",
    "AnalysisType",
    "Actor",
    "Base",
    "Campaign",
    "Indicator",
    "IndicatorType",
    "Investigation",
    "InvestigationStatus",
    "Kit",
    "KitStatus",
    "campaign_actors",
    "campaign_kits",
]
