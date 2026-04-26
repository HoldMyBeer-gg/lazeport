"""
Tests for Nessus (.nessus) and OpenVAS XML import functionality.

Covers parsing, severity mapping, host merging, and the upload endpoint.
"""
import hashlib
import pytest
from fastapi.testclient import TestClient

from app.api.findings import parse_nessus_xml, _merge_nessus_by_plugin, NessusFinding
from app.db import get_adapter
from app.main import app

client = TestClient(app)

# ── Minimal fixture XML ──────────────────────────────────────────────────────

NESSUS_XML_SINGLE = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.10">
      <ReportItem port="443" protocol="tcp" severity="3" pluginID="42873"
                  pluginName="SSL Medium Strength Cipher Suites Supported">
        <synopsis>The remote service supports the use of medium strength SSL ciphers.</synopsis>
        <description>The remote host supports the use of SSL ciphers that offer medium strength encryption.</description>
        <solution>Reconfigure the affected application to avoid the use of medium strength ciphers.</solution>
        <plugin_output>Medium Strength Ciphers supported by the remote service:\n  RC4-SHA Kx=RSA Au=RSA Enc=RC4(128) Mac=SHA1</plugin_output>
        <cvss3_base_score>5.3</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</cvss3_vector>
        <cve>CVE-2015-2808</cve>
        <see_also>https://www.openssl.org/docs/</see_also>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

NESSUS_XML_MULTI_HOST = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Multi Host Scan">
    <ReportHost name="10.0.0.1">
      <ReportItem port="80" protocol="tcp" severity="2" pluginID="11219"
                  pluginName="Nessus SYN scanner">
        <synopsis>It is possible to determine which TCP ports are open.</synopsis>
        <description>This plugin is a SYN 'half-open' port scanner.</description>
        <solution>Protect your target with an IP filter.</solution>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.2">
      <ReportItem port="80" protocol="tcp" severity="2" pluginID="11219"
                  pluginName="Nessus SYN scanner">
        <synopsis>It is possible to determine which TCP ports are open.</synopsis>
        <description>This plugin is a SYN 'half-open' port scanner.</description>
        <solution>Protect your target with an IP filter.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

NESSUS_XML_SKIP_PLUGIN_ZERO = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="192.168.1.1">
      <ReportItem port="0" protocol="tcp" severity="0" pluginID="0"
                  pluginName="Ping the remote host">
        <description>Host metadata plugin.</description>
      </ReportItem>
      <ReportItem port="22" protocol="tcp" severity="1" pluginID="10881"
                  pluginName="SSH Protocol Versions Supported">
        <synopsis>A SSH server is running on the remote host.</synopsis>
        <solution>n/a</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

OPENVAS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>SSH Weak Algorithms Supported</name>
      <threat>Medium</threat>
      <host>172.16.0.5</host>
      <port>22/tcp</port>
      <description>The remote SSH server supports weak encryption algorithms.</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.105611">
        <name>SSH Weak Algorithms Supported</name>
        <cvss_base>4.3</cvss_base>
        <cve>CVE-2016-6515</cve>
        <solution>Disable weak algorithms on the SSH server.</solution>
      </nvt>
    </result>
  </results>
</report>"""

BAD_XML = "this is not xml at all"

WRONG_ROOT_XML = """<?xml version="1.0" ?>
<SomeOtherTool><data>ignored</data></SomeOtherTool>"""


# ── Parser unit tests ────────────────────────────────────────────────────────

class TestParseNessusXml:
    def test_basic_nessus_parse(self):
        findings, tool = parse_nessus_xml(NESSUS_XML_SINGLE)
        assert tool == "Nessus"
        assert len(findings) == 1
        f = findings[0]
        assert f.pluginName == "SSL Medium Strength Cipher Suites Supported"
        assert f.severity == "High"  # severity="3"
        assert f.host == "192.168.1.10"
        assert f.port == "443/tcp"
        assert f.cvss3_base_score == "5.3"
        assert f.cve == "CVE-2015-2808"
        assert f.tool == "Nessus"

    def test_severity_mapping(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_SINGLE)
        assert findings[0].severity == "High"  # 3 → High

    def test_skips_plugin_id_zero(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_SKIP_PLUGIN_ZERO)
        assert len(findings) == 1
        assert findings[0].pluginName == "SSH Protocol Versions Supported"

    def test_multi_host_produces_multiple_findings(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_MULTI_HOST)
        assert len(findings) == 2
        hosts = {f.host for f in findings}
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts

    def test_invalid_xml_raises_400(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            parse_nessus_xml(BAD_XML)
        assert exc.value.status_code == 400

    def test_wrong_root_element_raises_400(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            parse_nessus_xml(WRONG_ROOT_XML)
        assert exc.value.status_code == 400

    def test_openvas_parse(self):
        findings, tool = parse_nessus_xml(OPENVAS_XML)
        assert tool == "OpenVAS"
        assert len(findings) == 1
        f = findings[0]
        assert f.pluginName == "SSH Weak Algorithms Supported"
        assert f.severity == "Medium"
        assert f.host == "172.16.0.5"
        assert f.cve == "CVE-2016-6515"
        assert f.cvss3_base_score == "4.3"
        assert f.tool == "OpenVAS"


class TestMergeNessusByPlugin:
    def test_merges_same_plugin_different_hosts(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_MULTI_HOST)
        merged = _merge_nessus_by_plugin(findings)
        assert len(merged) == 1
        m = merged[0]
        assert "10.0.0.1" in m["host"]
        assert "10.0.0.2" in m["host"]

    def test_no_merge_different_plugins(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_SKIP_PLUGIN_ZERO)
        # Only 1 finding after skip of pluginID 0
        merged = _merge_nessus_by_plugin(findings)
        assert len(merged) == 1

    def test_merged_dict_has_nessus_source_flag(self):
        findings, _ = parse_nessus_xml(NESSUS_XML_SINGLE)
        merged = _merge_nessus_by_plugin(findings)
        assert merged[0].get("nessus_source") is True


# ── Upload endpoint tests ────────────────────────────────────────────────────

class TestUploadNessusEndpoint:
    def test_upload_nessus_without_report_id(self):
        response = client.post(
            "/api/admin/findings/upload-nessus",
            files={"file": ("scan.nessus", NESSUS_XML_SINGLE.encode(), "application/xml")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["findings"][0]["pluginName"] == "SSL Medium Strength Cipher Suites Supported"

    def test_upload_nessus_with_report_id_creates_session(self):
        adapter = get_adapter()
        report = adapter.create_report("Nessus Test Report")
        response = client.post(
            f"/api/admin/findings/upload-nessus?report_id={report.id}",
            files={"file": ("scan.nessus", NESSUS_XML_SINGLE.encode(), "application/xml")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert data["total"] == 1

    def test_upload_openvas_xml(self):
        response = client.post(
            "/api/admin/findings/upload-nessus",
            files={"file": ("openvas.xml", OPENVAS_XML.encode(), "application/xml")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["findings"][0]["tool"] == "OpenVAS"

    def test_upload_bad_xml_returns_400(self):
        response = client.post(
            "/api/admin/findings/upload-nessus",
            files={"file": ("scan.nessus", BAD_XML.encode(), "application/xml")},
        )
        assert response.status_code == 400

    def test_upload_wrong_extension_returns_400(self):
        response = client.post(
            "/api/admin/findings/upload-nessus",
            files={"file": ("scan.csv", NESSUS_XML_SINGLE.encode(), "text/csv")},
        )
        assert response.status_code == 400

    def test_upload_oversized_file_returns_413(self):
        big_content = b"X" * (21 * 1024 * 1024)
        response = client.post(
            "/api/admin/findings/upload-nessus",
            files={"file": ("scan.nessus", big_content, "application/xml")},
        )
        assert response.status_code == 413


# ── Severity mapping completeness ────────────────────────────────────────────

class TestNessusSeverityMapping:
    def _make_xml(self, severity_int: str) -> str:
        return f"""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="S">
    <ReportHost name="1.2.3.4">
      <ReportItem port="80" protocol="tcp" severity="{severity_int}" pluginID="99999"
                  pluginName="Test Plugin">
        <synopsis>test</synopsis>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""

    @pytest.mark.parametrize("sev_int,expected", [
        ("0", "Informational"),
        ("1", "Low"),
        ("2", "Medium"),
        ("3", "High"),
        ("4", "Critical"),
    ])
    def test_severity_int_maps_correctly(self, sev_int, expected):
        findings, _ = parse_nessus_xml(self._make_xml(sev_int))
        assert findings[0].severity == expected
