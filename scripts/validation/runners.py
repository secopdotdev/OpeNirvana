"""Subprocess wrappers that normalize tool output into Findings.

Every runner takes an injectable `run` (defaults to subprocess.run) so unit tests
stay hermetic. Severity for security findings is tier-aware per the per-script matrix:
T0/T1 security issues BLOCK, T2 security issues WARN.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

from validation.model import Finding, Severity, Tier
from validation.tiers import tier_for


class _RunResult(Protocol):
    stdout: str | None
    returncode: int


RunFn = Callable[..., _RunResult]

# subprocess.run is a heavily-overloaded callable; pyright cannot assign the overload-union
# to RunFn structurally. cast() is the correct idiom — subprocess.run satisfies the
# protocol at runtime for every call site in this module (capture_output=True, text=True).
_DEFAULT_RUN: RunFn = cast(RunFn, subprocess.run)

_SECURITY_PREFIX = "S"  # ruff flake8-bandit codes start with S


def _missing(tool: str) -> list[Finding]:
    return [Finding(tool=tool, severity=Severity.WARN,
                    message=f"{tool} not installed (skipped)")]


def _sec_severity(file: str) -> Severity:
    return Severity.WARN if tier_for(file) is Tier.T2 else Severity.BLOCK


def run_ruff(paths: list[Path], *, run: RunFn = _DEFAULT_RUN) -> list[Finding]:
    cmd = [sys.executable, "-m", "ruff", "check", "--output-format", "json", *map(str, paths)]
    try:
        proc = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return _missing("ruff")
    try:
        rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [Finding(tool="ruff", severity=Severity.WARN,
                        message="could not parse ruff output")]
    findings: list[Finding] = []
    for r in rows:
        file = r.get("filename", "")
        code = r.get("code") or ""
        sev = _sec_severity(file) if code.startswith(_SECURITY_PREFIX) else Severity.WARN
        findings.append(Finding(
            tool="ruff", severity=sev, message=r.get("message", ""),
            file=file, line=(r.get("location") or {}).get("row"),
            tier=tier_for(file), rule=code,
        ))
    return findings


def run_pyright(paths: list[Path], *, run: RunFn = _DEFAULT_RUN) -> list[Finding]:
    cmd = [sys.executable, "-m", "pyright", "--outputjson", *map(str, paths)]
    try:
        proc = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return _missing("pyright")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [Finding(tool="pyright", severity=Severity.WARN,
                        message="could not parse pyright output")]
    findings: list[Finding] = []
    for d in data.get("generalDiagnostics", []):
        file = d.get("file", "")
        sev = Severity.BLOCK if d.get("severity") == "error" else Severity.WARN
        line0 = ((d.get("range") or {}).get("start") or {}).get("line")
        findings.append(Finding(
            tool="pyright", severity=sev, message=d.get("message", ""),
            file=file, line=(line0 + 1) if isinstance(line0, int) else None,
            tier=tier_for(file), rule=d.get("rule"),
        ))
    return findings


def run_bandit(paths: list[Path], *, run: RunFn = _DEFAULT_RUN) -> list[Finding]:
    """bandit -f json -r <paths>. Severity tier-aware. Same contract as run_ruff."""
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-r", *map(str, paths)]
    try:
        proc = run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return _missing("bandit")
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [Finding(tool="bandit", severity=Severity.WARN,
                        message="could not parse bandit output")]
    findings: list[Finding] = []
    # issue_severity/issue_confidence intentionally ignored -- the tier model governs gate severity.
    for r in data.get("results", []):
        file = r.get("filename", "")
        findings.append(Finding(
            tool="bandit", severity=_sec_severity(file),
            message=r.get("issue_text", ""), file=file,
            line=r.get("line_number"), tier=tier_for(file),
            rule=r.get("test_id"),
        ))
    return findings
