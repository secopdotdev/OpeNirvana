#!/usr/bin/env python3
"""utils_discovery — shared service-discovery primitives.

Single source of truth for parsing the stack's .env, Caddyfile, and
docker-compose so check-stack.py and gen-dashy-config.py agree on which
services exist, their current subdomains, and their backends.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


def load_env(path: Path) -> dict[str, str]:
    """Parse a .env file → {KEY: value}.

    Strips inline `# comments` and matched surrounding quotes, then does a
    one-pass `${VAR}` expansion using previously-seen values. Returns {} if
    the file is missing.
    """
    if not Path(path).exists():
        return {}
    raw: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.split("#")[0].strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            raw[key] = val
    resolved: dict[str, str] = {}
    for k, v in raw.items():
        resolved[k] = re.sub(r"\$\{(\w+)\}", lambda m: raw.get(m.group(1), ""), v)
    return resolved


def _brace_content(text: str, start: int) -> str:
    """Return content between matched braces, starting after the opening '{'."""
    depth, pos = 1, start
    while pos < len(text) and depth:
        c = text[pos]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        pos += 1
    return text[start : pos - 1]


def parse_caddyfile(path: Path, env: dict[str, str]) -> dict:
    """Return {backends, matchers, auth_exempt}.

    backends:    {service: upstream}            from (backend-X) snippets
    matchers:    {subdomain_value: service}     from handle @m {import backend-X}
                                                 AND dedicated {sub}.{fqdn} sites
    auth_exempt: {subdomain_value}              from @requires-auth-pub not host
    """
    text = Path(path).read_text(encoding="utf-8")

    def expand(s: str) -> str:
        return re.sub(r"\{\$(\w+)\}",
                      lambda m: env.get(m.group(1), f"{{{m.group(1)}}}"), s)

    text_exp = expand(text)
    public_fqdn = env.get("PUBLIC_FQDN", "")

    snippets: dict[str, str] = {}
    for m in re.finditer(r"\((\w[\w-]*)\)\s*\{", text_exp):
        snippets[m.group(1)] = _brace_content(text_exp, m.end())

    backends: dict[str, str] = {}
    for name, body in snippets.items():
        if not name.startswith("backend-"):
            continue
        service = name[len("backend-"):]
        m = re.search(r"reverse_proxy\s+([\w.\[\]/:_-]+)", body)
        if m:
            backends[service] = m.group(1).strip()

    matcher_to_subdomain: dict[str, str] = {}
    for m in re.finditer(
        r"@(\w[\w-]*)\s+\{?host\s+((?:[^\s{}\n]+(?:\s+[^\s{}\n]+)*)?)", text_exp):
        name = m.group(1)
        for host in m.group(2).split():
            if public_fqdn and host.endswith(f".{public_fqdn}"):
                matcher_to_subdomain[name] = host[: -(len(public_fqdn) + 1)]
                break
    for m in re.finditer(r"^\s*@(\w[\w-]*)\s+host\s+([\S]+)", text_exp, re.MULTILINE):
        name, host = m.group(1), m.group(2).strip()
        if public_fqdn and host.endswith(f".{public_fqdn}") and name not in matcher_to_subdomain:
            matcher_to_subdomain[name] = host[: -(len(public_fqdn) + 1)]

    matchers: dict[str, str] = {}
    for m in re.finditer(r"handle\s+@(\w[\w-]*)\s*\{", text_exp):
        block = _brace_content(text_exp, m.end())
        imp = re.search(r"import\s+backend-([\w-]+)", block)
        if imp:
            sub = matcher_to_subdomain.get(m.group(1))
            if sub:
                matchers[sub] = imp.group(1)

    # Dedicated top-level sites:  <sub>.<fqdn> { ... import backend-Y / reverse_proxy Z }
    # Skip wildcard (*.fqdn) and snippet ( (name) ) blocks.
    if public_fqdn:
        site_re = re.compile(
            r"(?m)^([A-Za-z0-9_.-]+)\.%s\s*\{" % re.escape(public_fqdn))
        for m in site_re.finditer(text_exp):
            sub = m.group(1)
            if sub.startswith("*") or sub.startswith("("):
                continue
            block = _brace_content(text_exp, m.end())
            imp = re.search(r"import\s+backend-([\w-]+)", block)
            if imp:
                matchers.setdefault(sub, imp.group(1))
                continue
            rp = re.search(r"reverse_proxy\s+([\w.-]+):\d+", block)
            if rp:
                matchers.setdefault(sub, rp.group(1))

    auth_exempt: set[str] = set()
    m = re.search(r"@requires-auth-pub\s*\{", text_exp)
    if m:
        block = _brace_content(text_exp, m.end())
        for m2 in re.finditer(r"not\s+host\s+([^\s\n]+)", block):
            host = m2.group(1).strip()
            if public_fqdn and host.endswith(f".{public_fqdn}"):
                auth_exempt.add(host[: -(len(public_fqdn) + 1)])

    return {"backends": backends, "matchers": matchers, "auth_exempt": auth_exempt}


def parse_compose_containers(
    compose_file: Path | None, env_file: Path | None
) -> tuple[dict[str, str], dict[str, str]]:
    """Run `docker compose config --format json` and return:
      ({service_name: container_name}, caddy_environment_dict)
    Falls back to service_name when container_name is not explicitly set.
    Returns ({}, {}) on any error. Uses docker compose so `${VAR}` references
    and YAML anchors are fully resolved (raw YAML parsing would not be).
    """
    cmd = ["docker", "compose"]
    if compose_file:
        cmd += ["-f", str(compose_file)]
    if env_file:
        cmd += ["--env-file", str(env_file)]
    cmd += ["config", "--format", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {}, {}
        data = json.loads(result.stdout)
        container_map = {
            svc: cfg.get("container_name", svc)
            for svc, cfg in data.get("services", {}).items()
        }
        caddy_env = data.get("services", {}).get("caddy", {}).get("environment", {})
        return container_map, caddy_env
    except Exception:
        return {}, {}
