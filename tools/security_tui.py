#!/usr/bin/env python3
"""
Security Findings Viewer - Interactive TUI for security scan results

🚀 PORTABLE - Copy this file to any project and use with any SARIF tool!

Universal viewer supporting multiple formats:
  - SARIF (Fluid Attacks, Semgrep, CodeQL, Snyk, Trivy, etc.)
  - ZAP XML
  - More formats coming soon

Features:
  - Mouse-clickable list
  - Preview pane with code context
  - Copy to clipboard for AI chat
  - Open file in Cursor at line
  - Filter by severity/tool
  - Keyboard shortcuts

Usage:
  python security_tui.py                              # Auto-discover all reports
  python security_tui.py report.sarif                 # Any SARIF file
  python security_tui.py results.xml                  # ZAP XML
  python security_tui.py --format sarif report.json   # Force format
  python security_tui.py scan1.sarif scan2.xml        # Multiple files

Portable - works in any project!
"""

import json
import os
import re
import subprocess
import sys
import defusedxml.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Static,
    TextArea,
)
from textual.binding import Binding


@dataclass
class Finding:
    """Security finding from any tool"""

    tool: str  # "Fluid Attacks", "ZAP", "Bandit", etc.
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None

    @property
    def severity_icon(self) -> str:
        """Get icon for severity"""
        icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
            "Note": "⚪",
        }
        return icons.get(self.severity, "⚪")

    @property
    def location(self) -> str:
        """Get human-readable location"""
        if self.file_path and self.line_number:
            return f"{self.file_path}:{self.line_number}"
        elif self.file_path:
            return self.file_path
        return "N/A"

    def to_ai_prompt(self) -> str:
        """Format as prompt for AI chat"""
        parts = [
            f"Fix this security issue:",
            f"",
            f"Tool: {self.tool}",
            f"Severity: {self.severity_icon} {self.severity}",
            f"Issue: {self.title}",
        ]

        if self.file_path:
            parts.append(f"Location: {self.location}")

        if self.cwe:
            parts.append(f"CWE: {self.cwe}")

        if self.cvss_score:
            parts.append(f"CVSS: {self.cvss_score}")

        parts.extend(["", "Description:", self.description])

        if self.code_snippet:
            parts.extend(["", "Code:", "```", self.code_snippet.strip(), "```"])

        if self.remediation:
            parts.extend(["", "Remediation:", self.remediation])

        return "\n".join(parts)


class FindingsParser:
    """Parse security findings from various tools"""

    @staticmethod
    def parse_sarif(file_path: str) -> List[Finding]:
        """Parse SARIF JSON from any tool (Fluid Attacks, Semgrep, CodeQL, etc.)"""
        findings = []
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            # Validate SARIF structure
            if not data.get("runs"):
                print(f"Invalid SARIF: no 'runs' found in {file_path}", file=sys.stderr)
                return findings

            for run in data["runs"]:
                # Extract tool name
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown Tool")
                
                # Build rules dictionary if available
                rules = {}
                if "rules" in run.get("tool", {}).get("driver", {}):
                    rules = {
                        rule["id"]: rule
                        for rule in run["tool"]["driver"]["rules"]
                    }

                # Parse results
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "unknown")
                    rule = rules.get(rule_id, {})

                    # Extract location (some tools may not have locations)
                    if not result.get("locations"):
                        continue
                    
                    location = result["locations"][0].get("physicalLocation", {})
                    artifact = location.get("artifactLocation", {})
                    region = location.get("region", {})
                    
                    file_path_loc = artifact.get("uri", "")
                    line = region.get("startLine", 0)
                    snippet = region.get("snippet", {}).get("text", "")

                    # Parse severity (SARIF uses level: none, note, warning, error)
                    level = result.get("level", "warning")
                    severity_map = {
                        "none": "Info",
                        "note": "Info",
                        "warning": "Medium",
                        "error": "High",
                    }
                    severity = severity_map.get(level, "Medium")
                    
                    # Try to get more specific severity from properties
                    props = result.get("properties", {})
                    if "cvss_v4_score" in props:
                        score = props["cvss_v4_score"]
                        if score >= 9.0:
                            severity = "Critical"
                        elif score >= 7.0:
                            severity = "High"
                        elif score >= 4.0:
                            severity = "Medium"
                        elif score > 0:
                            severity = "Low"

                    # Extract CWE
                    cwe = None
                    if "cwe_ids" in props and props["cwe_ids"]:
                        cwe = props["cwe_ids"][0]
                    elif "tags" in rule:
                        # Some tools put CWE in tags
                        cwe_tags = [tag for tag in rule.get("tags", []) if tag.startswith("CWE")]
                        if cwe_tags:
                            cwe = cwe_tags[0]

                    findings.append(
                        Finding(
                            tool=tool_name,
                            severity=severity,
                            title=rule.get("name") or rule.get("shortDescription", {}).get("text") or f"Rule {rule_id}",
                            description=(
                                rule.get("fullDescription", {}).get("text")
                                or rule.get("shortDescription", {}).get("text")
                                or result.get("message", {}).get("text", "")
                            ),
                            file_path=file_path_loc,
                            line_number=line if line > 0 else None,
                            code_snippet=snippet,
                            remediation=rule.get("help", {}).get("text", ""),
                            cwe=cwe,
                            cvss_score=props.get("cvss_v4_score"),
                        )
                    )
        except Exception as e:
            print(f"Error parsing SARIF from {file_path}: {e}", file=sys.stderr)

        return findings

    @staticmethod
    def parse_zap_xml(file_path: str) -> List[Finding]:
        """Parse ZAP XML report"""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for alert in root.findall(".//alertitem"):
                risk_desc = alert.find("riskdesc").text if alert.find("riskdesc") is not None else "Low"
                risk_level = risk_desc.split()[0] if risk_desc else "Low"

                # Map ZAP risk levels to our severity
                severity_map = {
                    "Informational": "Info",
                    "Low": "Low",
                    "Medium": "Medium",
                    "High": "High",
                }
                severity = severity_map.get(risk_level, "Low")

                name = alert.find("name").text if alert.find("name") is not None else "Unknown"
                desc = alert.find("desc").text if alert.find("desc") is not None else ""
                solution = alert.find("solution").text if alert.find("solution") is not None else ""
                uri = alert.find("uri").text if alert.find("uri") is not None else ""
                cwe_elem = alert.find("cweid")
                cwe = f"CWE-{cwe_elem.text}" if cwe_elem is not None and cwe_elem.text else None

                findings.append(
                    Finding(
                        tool="OWASP ZAP",
                        severity=severity,
                        title=name,
                        description=desc,
                        file_path=uri,
                        line_number=None,
                        code_snippet=None,
                        remediation=solution,
                        cwe=cwe,
                    )
                )
        except Exception as e:
            print(f"Error parsing ZAP XML: {e}", file=sys.stderr)

        return findings

    @staticmethod
    def detect_format(file_path: str) -> Optional[str]:
        """Detect file format from extension and content"""
        path = Path(file_path)
        
        # Check extension first
        if path.suffix in [".sarif", ".json"]:
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    # Check if it's SARIF
                    if "$schema" in data and "sarif" in data["$schema"].lower():
                        return "sarif"
                    if "runs" in data and isinstance(data["runs"], list):
                        return "sarif"
                    # Check if it's JSON but not SARIF
                    return None
            except:
                return None
        elif path.suffix == ".xml":
            return "zap_xml"
        
        return None

    @staticmethod
    def auto_discover() -> List[Finding]:
        """Auto-discover and parse all security reports"""
        findings = []

        # Find SARIF files (common patterns)
        for pattern in [
            "*.sarif",
            "**/*.sarif",
            "*-results.json",
            "**/*-results.json",
            "Fluid-Attacks-Results.json",
            "**/Fluid-Attacks-Results.json",
            "sarif-results/**/*.json",
        ]:
            for path in Path(".").glob(pattern):
                fmt = FindingsParser.detect_format(str(path))
                if fmt == "sarif":
                    findings.extend(FindingsParser.parse_sarif(str(path)))

        # Find ZAP results
        for pattern in ["zap-results/*/results-*.xml", "zap-results/*/*.xml", "zap*.xml"]:
            for path in Path(".").glob(pattern):
                findings.extend(FindingsParser.parse_zap_xml(str(path)))

        return findings


class FindingsViewer(App):
    """Interactive TUI for viewing security findings"""

    CSS = """
    Screen {
        background: $surface;
    }

    Header {
        background: $primary;
    }

    Footer {
        background: $primary;
    }

    #main-container {
        width: 100%;
        height: 100%;
    }

    #left-panel {
        width: 60%;
        height: 100%;
        border-right: solid $primary;
    }

    #right-panel {
        width: 40%;
        height: 100%;
        padding: 1;
    }

    #stats {
        height: 3;
        background: $boost;
        padding: 1;
        margin-bottom: 1;
    }

    #findings-table {
        height: 1fr;
    }

    #detail-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    #detail-content {
        height: 1fr;
        border: solid $primary;
        padding: 1;
    }

    #actions {
        height: auto;
        margin-top: 1;
        padding: 1;
        background: $boost;
    }

    Button {
        margin-right: 1;
    }

    .severity-critical {
        color: red;
    }

    .severity-high {
        color: orange;
    }

    .severity-medium {
        color: yellow;
    }

    .severity-low {
        color: dodgerblue;
    }

    .severity-info {
        color: gray;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("c", "copy", "Copy to clipboard"),
        Binding("o", "open_file", "Open in Cursor"),
        Binding("r", "refresh", "Refresh"),
        Binding("?", "help", "Help"),
    ]

    def __init__(self, findings: List[Finding]):
        super().__init__()
        self.findings = findings
        self.selected_finding: Optional[Finding] = None
        self.title = "Security Findings Viewer"
        self.sub_title = f"{len(findings)} findings"

    def compose(self) -> ComposeResult:
        """Create UI layout"""
        yield Header()

        with Horizontal(id="main-container"):
            with Vertical(id="left-panel"):
                yield Static(self._get_stats(), id="stats")
                yield DataTable(id="findings-table", cursor_type="row")

            with Vertical(id="right-panel"):
                yield Label("Select a finding to view details", id="detail-title")
                yield VerticalScroll(
                    Static("", id="detail-content"),
                )
                with Container(id="actions"):
                    yield Button("📋 Copy to Clipboard", id="copy-btn", variant="primary")
                    yield Button("📂 Open in Cursor", id="open-btn", variant="success")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the table"""
        table = self.query_one("#findings-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True

        # Add columns
        table.add_column("", width=3)  # Icon
        table.add_column("Tool", width=15)
        table.add_column("Severity", width=10)
        table.add_column("Issue", width=40)
        table.add_column("Location", width=30)

        # Add rows
        for i, finding in enumerate(self.findings):
            severity_class = f"severity-{finding.severity.lower()}"
            table.add_row(
                finding.severity_icon,
                finding.tool,
                finding.severity,
                finding.title[:40],
                finding.location[:30],
                key=str(i),
            )

    def _get_stats(self) -> str:
        """Get statistics summary"""
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        parts = [f"Total: {len(self.findings)}"]
        for severity in ["Critical", "High", "Medium", "Low", "Info", "Note"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                icon = Finding(tool="", severity=severity, title="", description="").severity_icon
                parts.append(f"{icon} {severity}: {count}")

        return " | ".join(parts)

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection"""
        idx = int(event.row_key.value)
        self.selected_finding = self.findings[idx]
        self._update_detail_panel()

    def _update_detail_panel(self) -> None:
        """Update the detail panel with selected finding"""
        if not self.selected_finding:
            return

        f = self.selected_finding

        # Update title
        title = self.query_one("#detail-title", Label)
        title.update(f"{f.severity_icon} {f.title}")

        # Build detail content
        lines = [
            f"[bold]Tool:[/bold] {f.tool}",
            f"[bold]Severity:[/bold] {f.severity}",
            f"[bold]Location:[/bold] {f.location}",
        ]

        if f.cwe:
            lines.append(f"[bold]CWE:[/bold] {f.cwe}")

        if f.cvss_score:
            lines.append(f"[bold]CVSS Score:[/bold] {f.cvss_score}")

        lines.extend([
            "",
            "[bold]Description:[/bold]",
            f.description[:500] + ("..." if len(f.description) > 500 else ""),
        ])

        if f.code_snippet:
            lines.extend([
                "",
                "[bold]Code:[/bold]",
                f"[dim]{f.code_snippet[:300]}[/dim]",
            ])

        if f.remediation:
            lines.extend([
                "",
                "[bold]Remediation:[/bold]",
                f.remediation[:300] + ("..." if len(f.remediation) > 300 else ""),
            ])

        content = self.query_one("#detail-content", Static)
        content.update("\n".join(lines))

    @on(Button.Pressed, "#copy-btn")
    def action_copy(self) -> None:
        """Copy finding to clipboard"""
        if not self.selected_finding:
            self.notify("No finding selected", severity="warning")
            return

        prompt = self.selected_finding.to_ai_prompt()

        try:
            # Try pbcopy (macOS)
            subprocess.run(["pbcopy"], input=prompt.encode(), check=True)
            self.notify("✓ Copied to clipboard! Paste into Cursor chat.", severity="information")
        except FileNotFoundError:
            try:
                # Try xclip (Linux)
                subprocess.run(["xclip", "-selection", "clipboard"], input=prompt.encode(), check=True)
                self.notify("✓ Copied to clipboard!", severity="information")
            except FileNotFoundError:
                self.notify("Clipboard not supported. Install pbcopy or xclip.", severity="error")

    @on(Button.Pressed, "#open-btn")
    def action_open_file(self) -> None:
        """Open file in Cursor at line"""
        if not self.selected_finding:
            self.notify("No finding selected", severity="warning")
            return

        f = self.selected_finding

        if not f.file_path:
            self.notify("No file path for this finding", severity="warning")
            return

        # Build goto argument
        if f.line_number:
            goto = f"{f.file_path}:{f.line_number}"
        else:
            goto = f.file_path

        try:
            # Try cursor CLI
            subprocess.run(["cursor", "--goto", goto], check=True)
            self.notify(f"✓ Opened {goto} in Cursor", severity="information")
        except FileNotFoundError:
            try:
                # Fallback to code (VSCode)
                subprocess.run(["code", "--goto", goto], check=True)
                self.notify(f"✓ Opened {goto} in VSCode", severity="information")
            except FileNotFoundError:
                self.notify("Cursor/VSCode CLI not found", severity="error")

    def action_refresh(self) -> None:
        """Refresh findings"""
        self.notify("Refreshing findings...", severity="information")
        # In a real implementation, re-parse files here
        self.notify("Refresh not implemented yet", severity="warning")

    def action_help(self) -> None:
        """Show help"""
        help_text = """
[bold]Keyboard Shortcuts:[/bold]

  q          Quit
  c          Copy to clipboard
  o          Open file in Cursor
  r          Refresh findings
  ?          Show this help
  ↑/↓        Navigate findings
  Enter      Select finding

[bold]Mouse:[/bold]

  Click on any finding to select it
  Click buttons to perform actions
        """
        self.notify(help_text.strip(), timeout=10)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Interactive security findings viewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Auto-discover all reports
  %(prog)s report.sarif                       # View SARIF file (any tool)
  %(prog)s results.xml                        # View ZAP XML
  %(prog)s --format sarif custom.json         # Force SARIF format
  %(prog)s scan1.sarif scan2.xml             # Multiple files

Supported formats:
  - SARIF: Fluid Attacks, Semgrep, CodeQL, Snyk, Trivy, etc.
  - ZAP XML: OWASP ZAP reports
        """
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Security report files to view (auto-detects format)"
    )
    parser.add_argument(
        "--format",
        choices=["sarif", "zap_xml", "auto"],
        default="auto",
        help="Force file format (default: auto-detect)"
    )
    
    args = parser.parse_args()
    
    findings = []

    # Parse command-line arguments for specific files
    if args.files:
        for file_path in args.files:
            path = Path(file_path)
            
            if not path.exists():
                print(f"File not found: {file_path}", file=sys.stderr)
                continue
            
            # Detect or use forced format
            if args.format == "auto":
                fmt = FindingsParser.detect_format(str(path))
            else:
                fmt = args.format
            
            # Parse based on format
            if fmt == "sarif":
                findings.extend(FindingsParser.parse_sarif(str(path)))
            elif fmt == "zap_xml":
                findings.extend(FindingsParser.parse_zap_xml(str(path)))
            elif path.suffix == ".json":
                # Try SARIF if JSON
                findings.extend(FindingsParser.parse_sarif(str(path)))
            elif path.suffix == ".xml":
                # Try ZAP if XML
                findings.extend(FindingsParser.parse_zap_xml(str(path)))
            else:
                print(f"Unknown file type: {file_path}", file=sys.stderr)
                print("  Use --format to specify format explicitly", file=sys.stderr)
    else:
        # Auto-discover
        findings = FindingsParser.auto_discover()

    if not findings:
        print("No security findings found.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Usage:", file=sys.stderr)
        print("  python security_tui.py                    # Auto-discover", file=sys.stderr)
        print("  python security_tui.py report.sarif       # Any SARIF file", file=sys.stderr)
        print("  python security_tui.py results.xml        # ZAP XML", file=sys.stderr)
        print("  python security_tui.py --format sarif file.json  # Force format", file=sys.stderr)
        print("", file=sys.stderr)
        print("This tool works with any project - just point it at your security reports!", file=sys.stderr)
        sys.exit(1)

    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Note": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 999), f.title))

    # Launch TUI
    app = FindingsViewer(findings)
    app.run()


if __name__ == "__main__":
    main()
