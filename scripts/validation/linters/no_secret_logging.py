"""Flag secret-named identifiers flowing into log/print/f-string sinks.

Encodes the Hard Invariant: secrets never written to disk/stdout in the clear.
Heuristic + AST, deliberately conservative (sink-scoped) to keep false positives low.

Detects secret-named values reached via bare name, attribute access, constant-key
subscript, and f-string interpolation of any of those, passed as positional OR
keyword arguments to a print()/logging-method sink.

Known limitations (documented trust boundary; not yet detected -- future phases):
  - %-format / str.format() argument lists: log.info("k=%s", secret) IS caught
    (secret is a positional arg) but "k={}".format(secret) is not.
  - String concatenation: print("k=" + secret).
  - Non-sink file handles: fh.write(secret).
  - Value aliasing / rename across statements (inherent AST-heuristic limit).
A non-compiling file returns a single WARN (fail-open: code that cannot run cannot
leak at runtime); the controller may escalate a Tier-0 WARN if desired.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from validation.model import Finding, Severity
from validation.tiers import tier_for

_TOOL = "no-secret-logging"

# Identifier substrings that denote secret material.
_SECRET_RE = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|apikey|role_id|secret_id|"
    r"unseal|private[_-]?key|client_secret|bearer)",
    re.IGNORECASE,
)

# logging method names that emit to a sink.
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}


def _expr_references_secret(node: ast.AST | None) -> bool:
    """True if an expression references secret material by name.

    Matches bare names (api_token), attribute access (self.token, obj.secret),
    constant-key subscripts (creds["password"], resp["data"]["token"]), and
    f-strings whose interpolated values reference any of the above (recursively).
    """
    if isinstance(node, ast.Name):
        return bool(_SECRET_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_SECRET_RE.search(node.attr)) or _expr_references_secret(node.value)
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str) \
                and _SECRET_RE.search(sl.value):
            return True
        return _expr_references_secret(node.value)
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(
            isinstance(v, ast.FormattedValue) and _expr_references_secret(v.value)
            for v in node.values
        )
    return False


def _is_sink(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        return True
    if isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS:
        return True
    return False


def scan_source(source: str, path: str) -> list[Finding]:
    """Scan Python source text; return findings (does not read the filesystem)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Finding(tool=_TOOL, severity=Severity.WARN,
                        message=f"could not parse: {e.msg}", file=path,
                        line=e.lineno, tier=tier_for(path))]

    findings: list[Finding] = []
    tier = tier_for(path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_sink(node):
            continue
        operands: list[ast.expr] = list(node.args) + [kw.value for kw in node.keywords]
        if any(_expr_references_secret(op) for op in operands):
            findings.append(Finding(
                tool=_TOOL, severity=Severity.BLOCK,
                message="secret-named value passed to a log/print sink",
                file=path, line=node.lineno, tier=tier, rule="SECRET-LOG",
            ))
    return findings


def scan_file(path: str | Path) -> list[Finding]:
    """Read a file and scan it (UTF-8). Non-UTF-8 or unreadable files return a single WARN."""
    p = Path(path)
    try:
        source = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        return [Finding(tool=_TOOL, severity=Severity.WARN,
                        message=f"could not read file: {e}", file=str(p),
                        tier=tier_for(str(p)))]
    return scan_source(source, str(p))
