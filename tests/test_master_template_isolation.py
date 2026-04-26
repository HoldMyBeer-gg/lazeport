"""
Master Template Organization Isolation Tests

Verifies that:
  1. Each org gets its own master template (not shared global)
  2. Org A cannot see or access Org B's master templates
  3. Uploading a template creates/updates only the org's own copy
  4. New orgs are provisioned with the factory default
  5. Listing templates returns only the org's own templates
"""
import uuid

import pytest
from app.db import get_adapter
from app.main import _load_factory_master_template


@pytest.fixture
def two_orgs_with_templates():
    """Two orgs, each with a user. Factory default templates provisioned."""
    adapter = get_adapter()
    adapter.init()
    suffix = uuid.uuid4().hex[:8]

    org_a = adapter.create_organization(
        name=f"Template Org A {suffix}", slug=f"tpl-org-a-{suffix}"
    )
    user_a = adapter.upsert_user(
        email=f"tpl-a-{suffix}@test.com", name="Template User A",
        provider="local", role="user",
    )
    adapter.create_organization_member(
        org_id=org_a.id, user_id=user_a.id, role="org_admin",
    )

    org_b = adapter.create_organization(
        name=f"Template Org B {suffix}", slug=f"tpl-org-b-{suffix}"
    )
    user_b = adapter.upsert_user(
        email=f"tpl-b-{suffix}@test.com", name="Template User B",
        provider="local", role="user",
    )
    adapter.create_organization_member(
        org_id=org_b.id, user_id=user_b.id, role="org_admin",
    )

    # Provision factory default for both orgs
    factory = _load_factory_master_template()
    if factory:
        adapter.create_master_template("master", factory, organization_id=org_a.id)
        adapter.create_master_template("master", factory, organization_id=org_b.id)

    yield {
        "adapter": adapter,
        "org_a": org_a, "user_a": user_a,
        "org_b": org_b, "user_b": user_b,
    }


class TestMasterTemplateIsolation:
    def test_each_org_has_own_master_template(self, two_orgs_with_templates):
        """Each org should have its own 'master' template record."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        tpl_a = adapter.get_master_template("master", d["org_a"].id)
        tpl_b = adapter.get_master_template("master", d["org_b"].id)

        assert tpl_a is not None, "Org A should have its own master template"
        assert tpl_b is not None, "Org B should have its own master template"
        assert tpl_a.id != tpl_b.id, "Templates should be distinct records"
        assert tpl_a.organization_id == d["org_a"].id
        assert tpl_b.organization_id == d["org_b"].id

    def test_list_returns_only_own_org_templates(self, two_orgs_with_templates):
        """Listing templates should return only the requesting org's templates."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        # Add a custom template to Org A
        adapter.create_master_template(
            "custom-report", b"custom content", organization_id=d["org_a"].id
        )

        list_a = list(adapter.list_master_templates(d["org_a"].id))
        list_b = list(adapter.list_master_templates(d["org_b"].id))

        names_a = {t.name for t in list_a}
        names_b = {t.name for t in list_b}

        assert "custom-report" in names_a
        assert "custom-report" not in names_b

    def test_get_template_does_not_cross_org(self, two_orgs_with_templates):
        """get_master_template should not return another org's template."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        adapter.create_master_template(
            "secret-methodology", b"org a secret", organization_id=d["org_a"].id
        )

        result = adapter.get_master_template("secret-methodology", d["org_b"].id)
        assert result is None, "Org B should not see Org A's template"

    def test_update_only_affects_own_org(self, two_orgs_with_templates):
        """Updating a template only changes the org's own copy."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        original_a = adapter.get_master_template("master", d["org_a"].id)
        original_b = adapter.get_master_template("master", d["org_b"].id)
        assert original_a is not None
        assert original_b is not None

        adapter.update_master_template("master", b"org a custom content", d["org_a"].id)

        updated_a = adapter.get_master_template("master", d["org_a"].id)
        unchanged_b = adapter.get_master_template("master", d["org_b"].id)

        assert updated_a.content == b"org a custom content"
        assert unchanged_b.content == original_b.content

    def test_delete_only_affects_own_org(self, two_orgs_with_templates):
        """Deleting a template only removes the org's own copy."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        adapter.delete_master_template("master", d["org_a"].id)

        assert adapter.get_master_template("master", d["org_a"].id) is None
        assert adapter.get_master_template("master", d["org_b"].id) is not None

    def test_update_nonexistent_returns_none(self, two_orgs_with_templates):
        """Updating a template that doesn't exist for this org returns None."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        result = adapter.update_master_template(
            "nonexistent", b"content", d["org_a"].id
        )
        assert result is None


class TestFindingTemplateIsolation:
    def test_finding_templates_isolated_by_org(self, two_orgs_with_templates):
        """Finding templates should only be visible to their own org."""
        d = two_orgs_with_templates
        adapter = d["adapter"]

        ft_a = adapter.create_finding_template(
            "Org A Finding Tpl", "## OrgA content", organization_id=d["org_a"].id
        )

        list_a = list(adapter.list_finding_templates(organization_id=d["org_a"].id))
        list_b = list(adapter.list_finding_templates(organization_id=d["org_b"].id))

        ids_a = {t.id for t in list_a}
        ids_b = {t.id for t in list_b}

        assert ft_a.id in ids_a
        assert ft_a.id not in ids_b
