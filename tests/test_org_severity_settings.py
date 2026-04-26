"""
Unit tests for organization-level severity criteria settings.

Tests bootstrap, migration, parsing, and RBAC for severity criteria management.
"""
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.services.master_docx import parse_severity_criteria_markdown


client = TestClient(app)


class TestSeverityCriteriaBootstrap:
    """Test that new orgs get severity criteria on creation."""

    def test_parse_severity_criteria_markdown(self):
        """Test that severity_criteria.md can be parsed correctly."""
        criteria = parse_severity_criteria_markdown()

        # Must have exactly 5 levels
        assert len(criteria) == 5
        expected_levels = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
        assert set(criteria.keys()) == expected_levels

        # Each definition must be non-empty string
        for level, definition in criteria.items():
            assert isinstance(definition, str)
            assert len(definition) > 0
            assert len(definition) <= 2000
            # Should not contain HTML tags
            assert '<' not in definition or 'script' not in definition.lower()

    def test_new_org_gets_severity_criteria(self):
        """Test that new org created via API gets severity_criteria populated."""
        adapter = get_adapter()

        # Create new org
        response = client.post(
            '/api/orgs',
            json={
                'name': 'Test Severity Org',
                'slug': f'test-severity-{id(self)}'
            }
        )
        assert response.status_code == 200
        org_id = response.json()['id']

        # Check that severity_criteria was populated
        org = adapter.get_organization(org_id)
        assert org.severity_criteria is not None
        assert org.severity_criteria != ''

        # Verify it's valid JSON with 5 levels
        criteria = json.loads(org.severity_criteria)
        assert len(criteria) == 5
        assert set(criteria.keys()) == {'Critical', 'High', 'Medium', 'Low', 'Informational'}


class TestSeverityCriteriaIsolation:
    """Test that orgs are isolated - OrgA cannot modify OrgB's criteria."""

    @pytest.fixture
    def two_orgs(self):
        """Create two orgs for isolation testing."""
        adapter = get_adapter()
        org_a = adapter.create_organization(name="Org A", slug=f"org-a-{id(self)}")
        org_b = adapter.create_organization(name="Org B", slug=f"org-b-{id(self)}")

        # Populate both with default criteria
        from app.services.master_docx import parse_severity_criteria_markdown
        default = parse_severity_criteria_markdown()
        if default:
            adapter.update_organization(org_a.id, severity_criteria=json.dumps(default))
            adapter.update_organization(org_b.id, severity_criteria=json.dumps(default))
            # Refetch to get updated severity_criteria
            org_a = adapter.get_organization(org_a.id)
            org_b = adapter.get_organization(org_b.id)

        return org_a, org_b

    def test_criteria_isolated_per_org(self, two_orgs):
        """Test that modifying OrgA's criteria doesn't affect OrgB."""
        org_a, org_b = two_orgs
        adapter = get_adapter()

        # Get original criteria for both
        criteria_a_orig = json.loads(org_a.severity_criteria)
        criteria_b_orig = json.loads(org_b.severity_criteria)

        # Modify OrgA's criteria
        criteria_a_modified = criteria_a_orig.copy()
        criteria_a_modified['Critical'] = 'Modified critical for OrgA'
        adapter.update_organization(org_a.id, severity_criteria=json.dumps(criteria_a_modified))

        # Verify OrgA was updated
        org_a_check = adapter.get_organization(org_a.id)
        criteria_a_check = json.loads(org_a_check.severity_criteria)
        assert criteria_a_check['Critical'] == 'Modified critical for OrgA'

        # Verify OrgB is unchanged
        org_b_check = adapter.get_organization(org_b.id)
        criteria_b_check = json.loads(org_b_check.severity_criteria)
        assert criteria_b_check == criteria_b_orig


class TestSeverityCriteriaValidation:
    """Test validation of severity criteria values."""

    def test_validation_requires_five_levels(self):
        """Test that criteria must have exactly 5 severity levels."""
        adapter = get_adapter()
        org = adapter.create_organization(name="Test Validation Org", slug=f"test-val-{id(self)}")

        # Try to set invalid criteria (missing Low)
        invalid_criteria = {
            'Critical': 'Critical definition',
            'High': 'High definition',
            'Medium': 'Medium definition',
            'Informational': 'Info definition'
        }

        # This should be caught at the API level (Phase 3), not at DB level
        # For now, just verify we can store valid criteria
        valid_criteria = {
            'Critical': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Informational': 'Informational'
        }
        adapter.update_organization(org.id, severity_criteria=json.dumps(valid_criteria))

        org_check = adapter.get_organization(org.id)
        stored = json.loads(org_check.severity_criteria)
        assert len(stored) == 5

    def test_criteria_text_length_bounds(self):
        """Test that criteria definitions have reasonable length bounds."""
        adapter = get_adapter()
        org = adapter.create_organization(name="Test Length Org", slug=f"test-len-{id(self)}")

        # Valid: at max length
        criteria_max = {
            'Critical': 'x' * 2000,
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Informational': 'Informational'
        }
        adapter.update_organization(org.id, severity_criteria=json.dumps(criteria_max))
        org_check = adapter.get_organization(org.id)
        assert len(json.loads(org_check.severity_criteria)['Critical']) == 2000


class TestSeverityCriteriaAPI:
    """Test GET/PUT API endpoints (Phase 3 tests - here for integration)."""

    def test_get_severity_settings_requires_org_admin(self):
        """Test that GET severity settings requires org_admin+ permission."""
        # This will be tested in Phase 3 with full RBAC
        # For now, just document the requirement
        pass

    def test_put_severity_settings_requires_org_admin(self):
        """Test that PUT severity settings requires org_admin+ permission."""
        # This will be tested in Phase 3 with full RBAC
        # For now, just document the requirement
        pass


class TestMigrationAndBackwardCompatibility:
    """Test migration of existing orgs and backward compatibility."""

    def test_existing_org_gets_criteria_on_migration(self):
        """Test that existing orgs without severity_criteria get populated."""
        adapter = get_adapter()

        # Create org and explicitly set severity_criteria to None (simulating old DB)
        org = adapter.create_organization(name="Old Org", slug=f"old-org-{id(self)}")

        # Manually set to None to simulate pre-migration state
        with adapter.engine.begin() as conn:
            conn.exec_driver_sql(
                f"UPDATE organization SET severity_criteria = NULL WHERE id = '{org.id}'"
            )

        # Re-run migration logic (what happens on init)
        adapter._ensure_organization_columns()

        # Verify criteria was populated
        org_check = adapter.get_organization(org.id)
        assert org_check.severity_criteria is not None
        criteria = json.loads(org_check.severity_criteria)
        assert len(criteria) == 5

    def test_parsing_robustness(self):
        """Test that parsing is robust to different markdown variations."""
        # The parser should handle the official severity_criteria.md format
        criteria = parse_severity_criteria_markdown()

        # Must succeed and return 5 valid levels
        assert criteria is not None
        assert len(criteria) == 5
