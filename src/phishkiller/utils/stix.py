"""STIX 2.1 helper functions for exporting PhishKiller data.

Provides utility functions to convert PhishKiller models into
STIX 2.1 objects for interoperability with threat intelligence platforms.
"""

from datetime import datetime, timezone

from stix2 import (
    URL,
    Bundle,
    EmailAddress,
    Identity,
    Indicator as STIXIndicator,
    IPv4Address,
    Malware,
    Relationship,
    ThreatActor,
)

# PhishKiller identity used as the creator of STIX objects
PHISHKILLER_IDENTITY = Identity(
    name="PhishKiller",
    identity_class="system",
    description="Automated phishing kit tracking and analysis platform",
)


def ioc_to_stix_indicator(
    ioc_type: str,
    ioc_value: str,
    confidence: int,
    kit_sha256: str | None = None,
) -> STIXIndicator:
    """Convert a PhishKiller IOC into a STIX Indicator object."""
    pattern_map = {
        "email": f"[email-addr:value = '{ioc_value}']",
        "telegram_bot_token": f"[artifact:payload_bin = '{ioc_value}']",
        "c2_url": f"[url:value = '{ioc_value}']",
        "ip_address": f"[ipv4-addr:value = '{ioc_value}']",
        "domain": f"[domain-name:value = '{ioc_value}']",
    }

    pattern = pattern_map.get(
        ioc_type,
        f"[artifact:payload_bin = '{ioc_value}']",
    )

    labels = ["malicious-activity", "phishing"]
    description = f"Phishing IOC ({ioc_type}): {ioc_value}"
    if kit_sha256:
        description += f" — extracted from kit SHA256:{kit_sha256[:16]}"

    return STIXIndicator(
        name=f"Phishing {ioc_type}: {ioc_value[:50]}",
        description=description,
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        labels=labels,
        confidence=confidence,
        created_by_ref=PHISHKILLER_IDENTITY.id,
    )


def kit_to_stix_malware(
    sha256: str,
    source_url: str,
    filename: str | None = None,
) -> Malware:
    """Convert a phishing kit into a STIX Malware object."""
    return Malware(
        name=filename or f"Phishing Kit ({sha256[:16]})",
        description=f"Phishing kit downloaded from {source_url}",
        malware_types=["webshell"],
        is_family=False,
        labels=["phishing-kit"],
        created_by_ref=PHISHKILLER_IDENTITY.id,
    )


def actor_to_stix_threat_actor(
    name: str,
    aliases: list[str] | None = None,
    description: str | None = None,
) -> ThreatActor:
    """Convert a PhishKiller actor into a STIX ThreatActor object."""
    return ThreatActor(
        name=name,
        aliases=aliases or [],
        description=description or f"Threat actor tracked by PhishKiller: {name}",
        threat_actor_types=["criminal"],
        sophistication="minimal",
        resource_level="individual",
        primary_motivation="personal-gain",
        created_by_ref=PHISHKILLER_IDENTITY.id,
    )


def create_bundle(*objects) -> Bundle:
    """Create a STIX Bundle from a collection of STIX objects."""
    return Bundle(objects=[PHISHKILLER_IDENTITY, *objects])
