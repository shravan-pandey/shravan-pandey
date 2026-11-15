"""Detects known-outdated client-side JS libraries loaded from common CDNs."""

from __future__ import annotations

import re

from ..findings import Finding, Report, Severity

NAME = "outdated-libraries"

# (regex matching a script src, library name, version group index, min-safe-version tuple, CVE note)
_LIB_PATTERNS = [
    (
        re.compile(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE),
        "jQuery",
        (3, 5, 0),
        "Versions before 3.5.0 have known XSS issues (e.g. CVE-2020-11022/11023 in "
        "`.html()`/`htmlPrefilter`).",
    ),
    (
        re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", re.IGNORECASE),
        "Bootstrap",
        (4, 3, 1),
        "Versions before 4.3.1 have known XSS issues in tooltip/popover/affix "
        "data attributes (CVE-2019-8331 and related).",
    ),
    (
        re.compile(r"angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE),
        "AngularJS",
        (1, 8, 0),
        "AngularJS (1.x) is end-of-life; multiple known sandbox-escape/XSS CVEs exist "
        "across the 1.x line. Migrating off AngularJS entirely is recommended.",
    ),
    (
        re.compile(r"lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE),
        "Lodash",
        (4, 17, 21),
        "Versions before 4.17.21 have prototype-pollution CVEs (e.g. CVE-2021-23337).",
    ),
    (
        re.compile(r"moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.IGNORECASE),
        "Moment.js",
        (2, 29, 4),
        "Versions before 2.29.4 have a ReDoS vulnerability (CVE-2022-31129); the "
        "library is also in maintenance mode — consider migrating to a modern "
        "alternative (date-fns, Luxon, Temporal).",
    ),
]


def _version_tuple(v: str):
    return tuple(int(x) for x in v.split("."))


def run(pages, session, report: Report, args) -> None:
    flagged = set()
    for page in pages:
        if not page.text:
            continue
        for pattern, lib_name, min_safe, note in _LIB_PATTERNS:
            for match in pattern.finditer(page.text):
                version_str = match.group(1)
                key = (lib_name, version_str)
                if key in flagged:
                    continue
                try:
                    version = _version_tuple(version_str)
                except ValueError:
                    continue
                if version < min_safe:
                    flagged.add(key)
                    report.add(
                        Finding(
                            check=NAME,
                            severity=Severity.MEDIUM,
                            title=f"Outdated {lib_name} {version_str} detected",
                            url=page.url,
                            evidence=f"Script reference matched `{match.group(0)}`.",
                            remediation=f"Upgrade {lib_name} to at least "
                            f"{'.'.join(map(str, min_safe))} (or latest). {note}",
                        )
                    )
