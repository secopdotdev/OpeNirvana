"""validate CLI -- discover targets, run runners + custom scanners, report, exit."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from validation import report, runners as _runners
from validation.linters import no_secret_logging
from validation.model import Finding

# This file is unified-stack/scripts/validation/cli.py, so parent.parent == unified-stack/scripts.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent

RunnerFn = Callable[[list[Path]], list[Finding]]
ScannerFn = Callable[[Path], list[Finding]]

DEFAULT_RUNNERS: list[RunnerFn] = [
    _runners.run_ruff,
    _runners.run_pyright,
    _runners.run_bandit,
]
DEFAULT_SCANNERS: list[ScannerFn] = [no_secret_logging.scan_file]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="validate.py",
                                description="Risk-tiered validation gate.")
    p.add_argument("--changed-only", action="store_true",
                   help="validate only files in the git diff vs origin/main")
    p.add_argument("--tier", type=int, choices=[0, 1, 2], default=None,
                   help="restrict to a single blast-radius tier")
    p.add_argument("--format", choices=["human", "json", "sarif"], default=None,
                   help="output format (default: human, or sarif under --ci)")
    p.add_argument("--fail-on", choices=["block", "warn"], default="block")
    p.add_argument("--ci", action="store_true",
                   help="CI mode: output defaults to SARIF unless --format is given")
    return p


def _git_diff_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", "origin/main...HEAD"],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        raise SystemExit(
            "validate: cannot compute changed files (git diff failed); "
            f"is origin/main fetched? {out.stderr.strip()}"
        )
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


def discover_targets(*, changed_only: bool,
                     git_diff_fn: Callable[[], list[str]] = _git_diff_files
                     ) -> list[Path]:
    if changed_only:
        return [Path(f) for f in git_diff_fn()
                if f.endswith(".py") and "scripts" in Path(f).parts]
    return sorted(SCRIPTS_DIR.glob("*.py"))


def run(args: argparse.Namespace, *,
        runners: Sequence[RunnerFn] | None = None,
        scanners: Sequence[ScannerFn] | None = None,
        discover: Callable[..., list[Path]] = discover_targets) -> int:
    runners = DEFAULT_RUNNERS if runners is None else runners
    scanners = DEFAULT_SCANNERS if scanners is None else scanners

    targets = discover(changed_only=args.changed_only)
    findings: list[Finding] = []
    if targets:  # never call runners with [] -- they would scan the whole CWD
        for r in runners:
            findings.extend(r(list(targets)))
        for path in targets:
            for s in scanners:
                findings.extend(s(path))

    if args.tier is not None:
        # keep tier=None findings (e.g. "tool not installed" WARNs) so they always surface
        findings = [f for f in findings if f.tier is None or int(f.tier) == args.tier]

    fmt = args.format or ("sarif" if args.ci else "human")
    if fmt == "sarif":
        print(json.dumps(report.render_sarif(findings), indent=2))
    elif fmt == "json":
        rendered = [
            {
                "tool": f.tool,
                "severity": f.severity.value,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "tier": int(f.tier) if f.tier is not None else None,
                "rule": f.rule,
            }
            for f in findings
        ]
        print(json.dumps(rendered, indent=2, default=str))
    else:
        print(report.render_human(findings))

    return report.exit_code(findings, fail_on=args.fail_on)


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
