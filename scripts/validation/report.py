"""Render findings to human text / SARIF and compute the process exit code."""

from __future__ import annotations

from typing import Literal

from validation.model import Finding, Severity

FailOn = Literal["block", "warn"]

_SEVERITY_ORDER = {Severity.BLOCK: 0, Severity.WARN: 1}


def exit_code(findings: list[Finding], fail_on: FailOn = "block") -> int:
    """1 if the gate should fail, else 0.

    block (default): fail only on BLOCK findings.
    warn: fail if any finding exists (used when ratcheting WARN->BLOCK).
    """
    if fail_on == "warn":
        return 1 if findings else 0
    return 1 if any(f.severity is Severity.BLOCK for f in findings) else 0


def _loc(f: Finding) -> str:
    if f.file and f.line is not None:
        return f"{f.file}:{f.line}"
    return f.file or "-"


def render_human(findings: list[Finding]) -> str:
    """Plain-text report in the check-stack.py house style."""
    if not findings:
        return "validate: no findings."
    lines = [f"validate: {len(findings)} finding(s)", ""]
    for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER.get(x.severity, 99), x.tool, _loc(x))):
        tier = f"T{int(f.tier)}" if f.tier is not None else "--"
        rule = f" [{f.rule}]" if f.rule else ""
        lines.append(f"  {f.severity.value:5} {tier} {f.tool:10} {_loc(f)}{rule}: {f.message}")
    return "\n".join(lines)


def render_sarif(findings: list[Finding]) -> dict[str, object]:
    """Minimal SARIF 2.1.0 doc for GitHub code-scanning upload."""
    results = []
    for f in findings:
        result: dict = {
            "ruleId": f.rule or f"{f.tool}/generic",
            "level": "error" if f.severity is Severity.BLOCK else "warning",
            "message": {"text": f.message},
        }
        if f.file:
            region: dict = {}
            if f.line is not None:
                region["startLine"] = f.line
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    **({"region": region} if region else {}),
                }
            }]
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "validate.py"}}, "results": results}],
    }
