"""Shared finding/severity model and Markdown report rendering."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    url: str
    evidence: str
    remediation: str


@dataclass
class Report:
    target: str
    pages_crawled: int = 0
    findings: list[Finding] = field(default_factory=list)
    started_at: _dt.datetime = field(default_factory=_dt.datetime.utcnow)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            grouped[f.severity].append(f)
        return grouped

    def summary_line(self) -> str:
        grouped = self.by_severity()
        parts = [
            f"{s.label}: {len(grouped[s])}"
            for s in sorted(Severity, reverse=True)
            if grouped[s]
        ]
        return ", ".join(parts) if parts else "No findings"

    def to_markdown(self) -> str:
        grouped = self.by_severity()
        lines = [
            f"# Security Scan Report: {self.target}",
            "",
            f"- Scanned at: {self.started_at.isoformat()}Z",
            f"- Pages crawled: {self.pages_crawled}",
            f"- Total findings: {len(self.findings)} ({self.summary_line()})",
            "",
            "---",
            "",
        ]
        for sev in sorted(Severity, reverse=True):
            items = grouped[sev]
            if not items:
                continue
            lines.append(f"## {sev.label} ({len(items)})")
            lines.append("")
            for i, f in enumerate(items, 1):
                lines.append(f"### {i}. {f.title}")
                lines.append(f"- **Check:** `{f.check}`")
                lines.append(f"- **URL:** {f.url}")
                lines.append(f"- **Evidence:** {f.evidence}")
                lines.append(f"- **Remediation:** {f.remediation}")
                lines.append("")
        if not self.findings:
            lines.append("No issues detected by the checks run. This is not a guarantee "
                          "of security — consider a manual review or professional pentest "
                          "for anything handling sensitive data.")
            lines.append("")
        return "\n".join(lines)
