"""Claim-path resolver — covers the four IdP shapes we ship support for.

The resolver has to handle: top-level keys (Entra/Okta), dotted-path
nested keys (Keycloak's ``realm_access.roles``), URL-namespaced keys
that contain dots (Auth0), and missing/malformed claims (return
``None`` / empty list, never crash).
"""

from __future__ import annotations

import pytest

from darla.auth.claims import claim_to_role_strings, resolve_claim_path


class TestResolveClaimPath:
    def test_top_level_key(self) -> None:
        # Entra and Okta both put roles at the top level.
        assert resolve_claim_path({"roles": ["Darla.Analyst"]}, "roles") == [
            "Darla.Analyst",
        ]

    def test_nested_dotted_path(self) -> None:
        # Keycloak nests roles inside realm_access.
        claims = {"realm_access": {"roles": ["Darla.Viewer", "other"]}}
        assert resolve_claim_path(claims, "realm_access.roles") == [
            "Darla.Viewer", "other",
        ]

    def test_url_namespaced_key_literal_match(self) -> None:
        # Auth0 uses URL-namespaced custom claims like
        # "https://your-app.example.com/roles".  The resolver must
        # treat this as a literal key, NOT walk the dotted parts —
        # otherwise it would look for "https:" → "//your-app" → ...
        # and find nothing.
        claims = {"https://your-app.example.com/roles": ["Darla.Analyst"]}
        got = resolve_claim_path(claims, "https://your-app.example.com/roles")
        assert got == ["Darla.Analyst"]

    def test_missing_top_level_returns_none(self) -> None:
        # Returning None (not raising) is the contract — middleware
        # turns "no role claim" into a clean 403 with a clear message.
        assert resolve_claim_path({"sub": "abc"}, "roles") is None

    def test_missing_nested_segment_returns_none(self) -> None:
        # Halfway-there nesting must not crash — happens when an IdP
        # token shape changes mid-rotation.
        assert resolve_claim_path({"realm_access": {}}, "realm_access.roles") is None

    def test_traverses_through_non_dict_returns_none(self) -> None:
        # If a path segment hits a non-dict (string, list, etc.), give
        # up cleanly — don't try to attribute-walk into it.
        assert resolve_claim_path(
            {"realm_access": "not-a-dict"}, "realm_access.roles",
        ) is None

    def test_empty_path_raises(self) -> None:
        # Empty config is operator error; surface it as a ValueError
        # at startup rather than a confusing 401 at request time.
        with pytest.raises(ValueError):
            resolve_claim_path({"a": 1}, "")

    def test_empty_segment_raises(self) -> None:
        # "..roles" or "realm_access..roles" is malformed config.
        with pytest.raises(ValueError):
            resolve_claim_path({"a": {"b": 1}}, "a..b")


class TestClaimToRoleStrings:
    def test_list_of_strings_passthrough(self) -> None:
        assert claim_to_role_strings(["Darla.Viewer", "Darla.Analyst"]) == [
            "Darla.Viewer", "Darla.Analyst",
        ]

    def test_single_string_wrapped(self) -> None:
        # Some IdPs emit a bare string when only one role is assigned.
        assert claim_to_role_strings("Darla.Analyst") == ["Darla.Analyst"]

    def test_none_becomes_empty(self) -> None:
        # Missing claim path resolves to None upstream — coerce to []
        # so the role-mapper sees a uniform shape.
        assert claim_to_role_strings(None) == []

    def test_keycloak_rpt_shape_unwrapped(self) -> None:
        # Keycloak's RPT (request party token) sometimes nests roles
        # inside another {"roles": [...]} even at the leaf — flatten.
        got = claim_to_role_strings({"roles": ["Darla.Analyst"]})
        assert got == ["Darla.Analyst"]

    def test_non_string_list_entries_filtered(self) -> None:
        # Defensive — a malformed token with mixed types in the role
        # array shouldn't crash the validator.  Drop non-strings.
        got = claim_to_role_strings(["Darla.Viewer", 42, None, "Darla.Analyst"])
        assert got == ["Darla.Viewer", "Darla.Analyst"]

    def test_unexpected_shape_becomes_empty(self) -> None:
        # Numbers, weird nested shapes — refuse to guess.  Empty list
        # → "no role" → 403, which is the safe default.
        assert claim_to_role_strings(42) == []
