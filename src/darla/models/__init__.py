"""All models imported here for Alembic autogeneration to detect them."""

from darla.models.actor import Actor
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.associations import (
    campaign_actors,
    campaign_kits,
    family_actors,
    family_kits,
    kit_actors,
)
from darla.models.base import Base
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator, IndicatorType
from darla.models.investigation import Investigation, InvestigationStatus
from darla.models.kit import Kit, KitStatus
from darla.models.monitored_domain import MonitoredDomain
from darla.models.victim import (
    KitVictim,
    Victim,
    VictimObservationSource,
    VictimType,
)

__all__ = [
    "AnalysisResult",
    "AnalysisType",
    "Actor",
    "Base",
    "Campaign",
    "Family",
    "Indicator",
    "IndicatorType",
    "Investigation",
    "InvestigationStatus",
    "Kit",
    "KitStatus",
    "KitVictim",
    "MonitoredDomain",
    "Victim",
    "VictimObservationSource",
    "VictimType",
    "campaign_actors",
    "campaign_kits",
    "family_actors",
    "family_kits",
    "kit_actors",
]
