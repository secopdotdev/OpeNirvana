"""utils_authentik_proxy - Authentik forward-auth proxy provider provisioning.

Behavior preserved from setup-authentik.py (deleted in Task 8). Reuses
utils.AuthentikClient instead of declaring its own; pagination is implemented
as a module-level helper because the shared client only exposes single-page
GETs.

Handles three cases per service:
  SKIP      - provider, app, and outpost binding are all correct; nothing to do.
  PROVISION - provider or app is missing; creates the absent objects.
  RENAME    - a *_SUBDOMAIN env var changed since last run; patches external_host
              on the existing provider and slug/meta_launch_url on the linked app.
"""

import datetime
import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from utils import AuthentikClient, EnvFile

_STACK_DIR = Path(__file__).resolve().parent.parent


# -- Load check-stack.py as a module (handles the hyphen in its filename) -----

def _load_check_stack():
    spec_path = Path(__file__).resolve().parent / "check-stack.py"
    spec = importlib.util.spec_from_file_location("check_stack", spec_path)
    assert spec is not None and spec.loader is not None, "Could not locate check-stack.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    setattr(mod, "_USE_COLOR", False)  # suppress ANSI in our output
    return mod


# -- Pagination helper (utils.AuthentikClient does not expose this) -----------

def _paginate(api: AuthentikClient, path: str,
              params: dict | None = None) -> list[dict]:
    """Walk Authentik's next-URL pagination and return concatenated 'results'."""
    qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
    url = f"{api.base_url}/api/v3{path}"
    if qs:
        url = f"{url}?{qs}"
    results: list[dict] = []
    while url:
        req = urllib.request.Request(url, method="GET", headers={
            "Authorization": f"Bearer {api.token}",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} GET {url}: {detail[:500]}") from exc
        results.extend(data.get("results", []))
        next_url = data.get("next")
        if not next_url:
            break
        # Rewrite host to match configured base in case container returns its internal hostname.
        parsed = urlparse(next_url)
        base_parsed = urlparse(api.base_url)
        url = next_url.replace(
            f"{parsed.scheme}://{parsed.netloc}",
            f"{base_parsed.scheme}://{base_parsed.netloc}",
        )
    return results


# -- Helpers ------------------------------------------------------------------

def _get_app_by_slug(client: AuthentikClient, slug: str) -> dict | None:
    """Fetch an application by slug; return None on 404."""
    try:
        return client.get(f"/core/applications/{slug}/")
    except RuntimeError as e:
        if "HTTP 404" in str(e):
            return None
        raise


def _provider_patch_body(provider: dict, **overrides) -> dict:
    """
    Build a PATCH body for /providers/proxy/{pk}/ that satisfies Authentik's
    serializer validation.  Authentik requires mode + flow fields even on
    partial updates; sending only the changed field(s) results in a 400.
    """
    body: dict = {
        "name":                provider["name"],
        "external_host":       provider["external_host"],
        "mode":                provider.get("mode", "forward_single"),
        "authentication_flow": provider.get("authentication_flow"),
        "authorization_flow":  provider.get("authorization_flow"),
        "invalidation_flow":   provider.get("invalidation_flow"),
    }
    body.update(overrides)
    return body


def _load_output(path: Path) -> dict | None:
    """Load previous output JSON; return None if missing or unreadable."""
    try:
        with path.open() as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _snapshots_equal(current: list[dict], previous: list[dict]) -> bool:
    """Return True when the two service lists are identical (sorted by env_var)."""
    if len(current) != len(previous):
        return False
    key = lambda x: x["env_var"]  # noqa: E731
    return sorted(current, key=key) == sorted(previous, key=key)


def _find_flows(client: AuthentikClient) -> tuple[str | None, str | None, str | None]:
    """Return (authentication_flow_pk, authorization_flow_pk, invalidation_flow_pk)."""
    flows = _paginate(client, "/flows/instances/")
    auth_pk = authz_pk = None
    inv_flows: list[dict] = []
    for f in flows:
        slug = f.get("slug", "")
        designation = f.get("designation", "")
        if designation == "authentication" and not auth_pk:
            auth_pk = f["pk"]
        if designation == "authorization" and "implicit" in slug and not authz_pk:
            authz_pk = f["pk"]
        if designation == "invalidation":
            inv_flows.append(f)
    inv_pk = next(
        (f["pk"] for f in inv_flows if "provider" in f.get("slug", "")),
        inv_flows[0]["pk"] if inv_flows else None,
    )
    return auth_pk, authz_pk, inv_pk


# -- Entry point --------------------------------------------------------------

def run(args, env: EnvFile) -> int:
    """Idempotently provision/repair Authentik proxy applications.

    args fields used: caddyfile, authentik_url, output_dir, dry_run.
    """
    cs = _load_check_stack()

    env_path = env.path
    caddyfile_path = Path(args.caddyfile)
    for p in (env_path, caddyfile_path):
        if not p.exists():
            print(f"ERROR: File not found: {p}", file=sys.stderr)
            return 1

    env_dict = cs.load_env(env_path)
    caddy = cs.parse_caddyfile(caddyfile_path, env_dict)

    domain   = env_dict.get("PUBLIC_FQDN", "")
    ak_token = env_dict.get("AUTHENTIK_BOOTSTRAP_TOKEN", "")

    if not domain:
        print("ERROR: PUBLIC_FQDN not set in .env", file=sys.stderr)
        return 1
    if not ak_token:
        print("ERROR: AUTHENTIK_BOOTSTRAP_TOKEN not set in .env", file=sys.stderr)
        return 1

    # -- Determine target subdomains -----------------------------------------
    # forward-auth = has a Caddyfile backend, is not the Authentik IDP itself,
    # and is not in the @requires-auth-pub NOT-host list (native-OIDC services).
    authentik_sub = env_dict.get("AUTHENTIK_SUBDOMAIN", "auth")
    subdomain_vars = {
        k: v for k, v in env_dict.items()
        if k.endswith("_SUBDOMAIN") and v.strip()
    }

    seen: set[str] = set()
    targets: list[tuple[str, str]] = []  # [(subdomain, env_var)]
    for env_var, sub in sorted(subdomain_vars.items(), key=lambda x: x[1]):
        if sub in seen:
            continue
        seen.add(sub)
        if sub == authentik_sub:
            continue                        # Authentik itself
        if sub in caddy["auth_exempt"]:
            continue                        # native-OIDC (Nextcloud, Jellyfin, etc.)
        if sub not in caddy["matchers"]:
            continue                        # no Caddyfile backend -> not an external web service
        targets.append((sub, env_var))

    print(f"Forward-auth subdomains to provision ({len(targets)}):")
    for sub, env_var in targets:
        print(f"  {sub}.{domain}  [{env_var}]")

    if not targets:
        print("Nothing to do.")
        return 0

    if args.dry_run:
        print("\n[DRY RUN] No API calls will be made.")

    # -- Query current Authentik state ---------------------------------------
    print(f"\nQuerying Authentik at {args.authentik_url} ...")
    api = AuthentikClient(args.authentik_url, ak_token)

    existing_providers = _paginate(api, "/providers/proxy/")
    # Index by external_host (normalized: no trailing slash)
    provider_by_host: dict[str, dict] = {
        p["external_host"].rstrip("/"): p for p in existing_providers
    }
    # Index by name - stable key for rename detection when external_host changed
    provider_by_name: dict[str, dict] = {p["name"]: p for p in existing_providers}
    print(f"  {len(existing_providers)} existing proxy provider(s)")

    existing_apps = _paginate(api, "/core/applications/")
    # Note: on some Authentik versions the paginated list returns empty results
    # even when applications exist.  Per-slug GET is reliable; we use that as
    # the canonical lookup inside the loop.  The list is kept for informational
    # purposes only.
    app_by_slug: dict[str, dict] = {a["slug"]: a for a in existing_apps}
    print(f"  {len(existing_apps)} existing application(s) via list (per-slug GET used for accuracy)")

    outposts = _paginate(api, "/outposts/instances/", {"type": "proxy"})
    if not outposts:
        print("ERROR: no proxy outpost found", file=sys.stderr)
        return 1
    # Prefer the external (non-managed) proxy outpost; fall back to first if
    # only the embedded outpost exists (e.g. fresh install before first run).
    outpost = next(
        (o for o in outposts if o.get("managed") is None),
        outposts[0],
    )
    outpost_pk: str = outpost["pk"]
    outpost_providers: list[int] = list(outpost.get("providers", []))
    print(f"  Outpost '{outpost['name']}' (pk={outpost_pk}): {len(outpost_providers)} provider(s)")

    # -- Resolve flow UUIDs --------------------------------------------------
    print("  Querying flows ...")
    auth_flow_pk, authz_flow_pk, inv_flow_pk = _find_flows(api)
    if not auth_flow_pk or not authz_flow_pk or not inv_flow_pk:
        print("ERROR: could not resolve flow UUIDs", file=sys.stderr)
        return 1

    # -- Build current-state snapshot (no extra API calls) -------------------
    current_snapshot: list[dict] = []
    for _sub, _env_var in targets:
        _svc_key = _env_var[: -len("_SUBDOMAIN")].lower()
        _ext     = f"https://{_sub}.{domain}"
        _prov    = (provider_by_host.get(_ext.rstrip("/"))
                    or provider_by_name.get(f"{_svc_key}-proxy-provider"))
        _pk      = _prov["pk"] if _prov else None
        current_snapshot.append({
            "env_var":              _env_var,
            "subdomain":            _sub,
            "compose_service":      caddy["matchers"].get(_sub, ""),
            "external_host":        _ext,
            "provider_name":        _prov["name"] if _prov else None,
            "app_slug":             _prov.get("assigned_application_slug") if _prov else None,
            "in_outpost":           (_pk in outpost_providers) if _pk is not None else False,
            "authorization_flow_ok": (
                _prov.get("authorization_flow") == authz_flow_pk if _prov else False
            ),
        })

    # -- Compare against previous run; exit early if nothing changed ---------
    output_dir  = Path(args.output_dir)
    output_path = output_dir / "setup-authentik-output.json"
    prev_output = _load_output(output_path)
    if prev_output is not None:
        if _snapshots_equal(current_snapshot, prev_output.get("services", [])):
            print("\nState unchanged since last run - nothing to do.")
            return 0
        print(f"\nState changed since last run.")
    else:
        print(f"\nNo previous output at {output_path}; running full reconciliation.")

    # -- Provision / rename each target --------------------------------------
    new_provider_pks: list[int] = []
    matched_pks: set[int] = set()
    service_states: list[dict] = []
    snapshot_by_var: dict[str, dict] = {s["env_var"]: s for s in current_snapshot}

    for sub, env_var in targets:
        service_key   = env_var[: -len("_SUBDOMAIN")].lower()
        external_host = f"https://{sub}.{domain}"
        host_key      = external_host.rstrip("/")
        new_slug      = sub.replace(".", "-")
        provider_name = f"{service_key}-proxy-provider"

        # Phase 1: provider already has the current external_host
        provider  = provider_by_host.get(host_key)
        is_rename = False

        # Phase 2: provider exists under the stable service-key name (subdomain changed)
        if provider is None:
            provider = provider_by_name.get(provider_name)
            if provider is not None:
                is_rename = True

        provider_pk: int | None = provider["pk"] if provider else None
        if provider_pk is not None:
            matched_pks.add(provider_pk)

        # Phase 1 match with a legacy subdomain-based name -> normalize to stable key name
        needs_name_normalize = (
            provider is not None
            and not is_rename
            and provider["name"] != provider_name
        )
        if needs_name_normalize:
            _name_taken = provider_by_name.get(provider_name)
            if _name_taken is not None and _name_taken["pk"] != provider_pk:
                needs_name_normalize = False

        # App lookup: list may be unreliable so always verify via per-slug GET.
        app = app_by_slug.get(new_slug) or _get_app_by_slug(api, new_slug)
        if app is None and provider is not None:
            assigned = provider.get("assigned_application_slug")
            if assigned and assigned != new_slug:
                app = _get_app_by_slug(api, assigned)
        app_needs_rename = app is not None and app["slug"] != new_slug

        already_in_outpost = provider_pk is not None and provider_pk in outpost_providers

        needs_authz_flow_fix = (
            provider is not None
            and provider.get("authorization_flow") != authz_flow_pk
        )

        if (provider_pk is not None and not is_rename and not needs_name_normalize
                and not needs_authz_flow_fix
                and app is not None and not app_needs_rename and already_in_outpost):
            print(f"  SKIP      {sub}.{domain}  (provider + app + outpost already present)")
            service_states.append(snapshot_by_var[env_var])
            continue

        action_parts: list[str] = []
        if is_rename:
            assert provider is not None  # is_rename=True only set when provider is not None
            action_parts.append(f"rename provider ({provider['external_host']} -> {external_host})")
        elif provider is None:
            action_parts.append("create provider")
        elif needs_name_normalize:
            action_parts.append(f"normalize provider name ('{provider['name']}' -> '{provider_name}')")
        if needs_authz_flow_fix:
            action_parts.append("fix authorization_flow (was authentication, must be implicit-consent)")
        if app_needs_rename:
            assert app is not None  # app_needs_rename=True only set when app is not None
            action_parts.append(f"rename app (slug '{app['slug']}' -> '{new_slug}')")
        elif app is None:
            action_parts.append("create app")
        if not already_in_outpost:
            action_parts.append("add to outpost")
        label = "RENAME   " if is_rename else "PROVISION"
        print(f"  {label}  {sub}.{domain}  ({', '.join(action_parts)})")

        if args.dry_run:
            continue

        # Rename provider, normalize its name, create it, or repair its flows
        if is_rename:
            assert provider is not None  # is_rename=True only set when provider is not None
            overrides: dict = {"external_host": external_host}
            if needs_authz_flow_fix:
                overrides["authorization_flow"] = authz_flow_pk
            api.patch(f"/providers/proxy/{provider_pk}/",
                      _provider_patch_body(provider, **overrides))
            print(f"            patched provider pk={provider_pk}: external_host -> {external_host}")
        elif provider is None:
            resp = api.post("/providers/proxy/", {
                "name":                provider_name,
                "authentication_flow": auth_flow_pk,
                "authorization_flow":  authz_flow_pk,
                "invalidation_flow":   inv_flow_pk,
                "external_host":       external_host,
                "mode":                "forward_single",
            })
            provider_pk = int(resp["pk"])
            matched_pks.add(provider_pk)
            print(f"            created provider pk={provider_pk}")
        else:
            patch_overrides: dict = {}
            if needs_name_normalize:
                patch_overrides["name"] = provider_name
            if needs_authz_flow_fix:
                patch_overrides["authorization_flow"] = authz_flow_pk
            if patch_overrides:
                api.patch(f"/providers/proxy/{provider_pk}/",
                          _provider_patch_body(provider, **patch_overrides))
                if needs_name_normalize:
                    print(f"            normalized provider name: '{provider['name']}' -> '{provider_name}'")
                if needs_authz_flow_fix:
                    print(f"            fixed authorization_flow on provider pk={provider_pk}")
            else:
                print(f"            reusing existing provider pk={provider_pk}")

        # Rename app or create it
        if app_needs_rename:
            assert app is not None  # app_needs_rename=True only set when app is not None
            # Authentik's application endpoint uses slug (not pk) as the URL key.
            api.patch(f"/core/applications/{app['slug']}/", {
                "name":            sub,
                "slug":            new_slug,
                "meta_launch_url": external_host,
            })
            print(f"            patched app '{app['slug']}': slug -> '{new_slug}'")
        elif app is None:
            resp = api.post("/core/applications/", {
                "name":            sub,
                "slug":            new_slug,
                "provider":        provider_pk,
                "meta_launch_url": external_host,
            })
            print(f"            created application '{resp['slug']}'")

        if provider_pk is not None and provider_pk not in outpost_providers:
            new_provider_pks.append(provider_pk)

        service_states.append({
            "env_var":         env_var,
            "subdomain":       sub,
            "compose_service": caddy["matchers"].get(sub, ""),
            "external_host":   external_host,
            "provider_name":   provider_name,
            "app_slug":        new_slug,
            "in_outpost":      True,
        })

    # -- Patch outpost once with all new providers ---------------------------
    if new_provider_pks and not args.dry_run:
        updated = sorted(set(outpost_providers + new_provider_pks))
        api.patch(f"/outposts/instances/{outpost_pk}/", {"providers": updated})
        print(f"\nPatched outpost '{outpost['name']}': added {len(new_provider_pks)} provider(s)")
    elif new_provider_pks and args.dry_run:
        print(f"\n[DRY RUN] Would patch outpost with {len(new_provider_pks)} new provider pk(s)")
    else:
        print("\nNo outpost changes needed.")

    # -- Orphan report -------------------------------------------------------
    orphans = [p for p in existing_providers if p["pk"] not in matched_pks]
    if orphans:
        print("\nOrphaned proxy providers (not matched to any forward-auth target):")
        for p in orphans:
            print(f"  WARNING: '{p['name']}' external_host={p['external_host']}")

    # -- Write output file ---------------------------------------------------
    if not args.dry_run and service_states:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_payload = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "domain":       domain,
            "services":     service_states,
        }
        output_path.write_text(json.dumps(output_payload, indent=2))
        print(f"\nOutput written to {output_path}")

    print("Done.")
    return 0
