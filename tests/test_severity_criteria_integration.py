"""Tests for org-level severity criteria integration with LLM generation."""
import json
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from app.db import get_adapter
from app.main import app
from app.db.models import SYSTEM_ORG_ID

client = TestClient(app)


class TestSeverityCriteriaLoading:
    """Test that severity criteria are loaded from org and passed to LLM."""

    def test_load_severity_criteria_from_org_success(self):
        """Test _load_severity_criteria_from_org with valid criteria."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()

        # Create an organization
        org = adapter.create_organization(
            name="Test Org",
            slug="test-org",
        )

        # Set severity criteria
        criteria_dict = {
            "Critical": "Evidence of previous compromise or trivial exploitation",
            "High": "Significant compromise possible with weak auth",
            "Medium": "Limited disclosure; non-trivial exploitation required",
            "Low": "Minimal impact; difficult to exploit",
            "Informational": "Security-relevant insight only",
        }
        adapter.update_organization(
            org.id,
            severity_criteria=json.dumps(criteria_dict),
        )

        # Load and verify
        loaded = _load_severity_criteria_from_org(org.id, adapter)
        assert loaded == criteria_dict

    def test_load_severity_criteria_from_org_missing_level(self):
        """Test that incomplete criteria (missing a level) returns None."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()

        # Create org
        org = adapter.create_organization(
            name="Incomplete Org",
            slug="incomplete-org",
        )

        # Set incomplete criteria (missing "Low")
        incomplete_criteria = {
            "Critical": "def",
            "High": "def",
            "Medium": "def",
            "Informational": "def",
        }
        adapter.update_organization(
            org.id,
            severity_criteria=json.dumps(incomplete_criteria),
        )

        # Load should return None due to missing level
        loaded = _load_severity_criteria_from_org(org.id, adapter)
        assert loaded is None

    def test_load_severity_criteria_from_org_invalid_json(self):
        """Test that invalid JSON in severity_criteria returns None."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()

        # Create org
        org = adapter.create_organization(
            name="Invalid Org",
            slug="invalid-org",
        )

        # Set invalid JSON
        adapter.update_organization(
            org.id,
            severity_criteria="{not valid json",
        )

        # Load should return None
        loaded = _load_severity_criteria_from_org(org.id, adapter)
        assert loaded is None

    def test_load_severity_criteria_from_org_none_org_id(self):
        """Test that None org_id returns None."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()
        loaded = _load_severity_criteria_from_org(None, adapter)
        assert loaded is None

    def test_org_criteria_takes_priority_over_none(self):
        """When org has criteria, _load_severity_criteria_from_org returns it (not None)."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()
        org = adapter.create_organization(name="Priority Org", slug="priority-org-unit")
        criteria = {
            "Critical": "Org crit",
            "High": "Org high",
            "Medium": "Org med",
            "Low": "Org low",
            "Informational": "Org info",
        }
        adapter.update_organization(org.id, severity_criteria=json.dumps(criteria))

        result = _load_severity_criteria_from_org(org.id, adapter)
        assert result is not None
        assert result["Critical"] == "Org crit"

    def test_fallback_when_org_has_no_criteria(self):
        """When org has no criteria, _load_severity_criteria_from_org returns None (caller falls back)."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()
        org = adapter.create_organization(name="Empty Org", slug="empty-org-unit")
        # No severity_criteria set

        result = _load_severity_criteria_from_org(org.id, adapter)
        assert result is None

    def test_org_criteria_priority_logic(self):
        """Simulate the priority logic: org criteria wins over a mock template result."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()
        org = adapter.create_organization(name="Prio Logic Org", slug="prio-logic-org-unit")
        org_criteria = {
            "Critical": "ORG_SPECIFIC_CRITICAL",
            "High": "ORG_SPECIFIC_HIGH",
            "Medium": "ORG_SPECIFIC_MEDIUM",
            "Low": "ORG_SPECIFIC_LOW",
            "Informational": "ORG_SPECIFIC_INFO",
        }
        adapter.update_organization(org.id, severity_criteria=json.dumps(org_criteria))

        # Simulate endpoint logic: try org first, fall back to template
        severity_criteria = _load_severity_criteria_from_org(org.id, adapter)
        if not severity_criteria:
            severity_criteria = {"Critical": "TEMPLATE_FALLBACK"}  # would not reach

        assert severity_criteria["Critical"] == "ORG_SPECIFIC_CRITICAL"
        assert "TEMPLATE_FALLBACK" not in severity_criteria.values()

    def test_fallback_logic_uses_template_when_org_empty(self):
        """Simulate the priority logic: falls back to template when org has no criteria."""
        from app.api.generate import _load_severity_criteria_from_org

        adapter = get_adapter()
        org = adapter.create_organization(name="No Crit Org", slug="no-crit-org-unit")
        # No severity_criteria set

        severity_criteria = _load_severity_criteria_from_org(org.id, adapter)
        if not severity_criteria:
            severity_criteria = {"Critical": "TEMPLATE_FALLBACK"}

        assert severity_criteria["Critical"] == "TEMPLATE_FALLBACK"
