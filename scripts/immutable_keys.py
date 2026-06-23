"""immutable_keys.py — Credential-immutability registry for the unified stack.

Single source of truth for environment variables that MUST NOT be rotated in
place after first deployment, because doing so breaks on-disk encrypted state
or invalidates credentials held by an external system.

No third-party dependencies, no I/O — pure data + logic. Safe to import on
any platform.

Usage pattern (callers call before any .env write):
    from immutable_keys import assert_immutable, is_immutable

Design rationale: ADR-0017 (credential immutability registry).
"""
from __future__ import annotations


# ── Registry ──────────────────────────────────────────────────────────────────
#
# Each entry: key → human-readable reason. The reason is shown verbatim in the
# ValueError raised by assert_immutable(), so the developer running a rotation
# sees *why* the key is frozen, not just that it is.
#
# Inclusion criterion: rotating the key in place breaks either
#   (a) on-disk encrypted state that cannot be re-derived, or
#   (b) a value also held by an external system where automatic re-sync is
#       impossible (a phone, a printed recovery sheet, the Nextcloud Talk UI).
#
# When in doubt: add the key. A false positive costs a deliberate rotation
# procedure; a false negative costs lost data.

IMMUTABLE_KEYS: dict[str, str] = {
    # ── Application session / credential encryption ────────────────────────────
    "AUTHENTIK_SECRET_KEY":
        "encrypts Authentik session cookies + stored credentials; "
        "rotation invalidates every active session AND every stored upstream secret.",
    "N8N_ENCRYPTION_KEY":
        "encrypts n8n stored workflow credentials (OAuth tokens, API keys); "
        "rotation makes every saved credential unrecoverable.",
    "TANDOOR_SECRET_KEY":
        "Django-style session/CSRF key; rotation invalidates active logins "
        "and breaks any encrypted persistent fields.",
    "VIKUNJA_JWT_SECRET":
        "signs Vikunja user JWTs; rotation logs every user out AND invalidates "
        "any cached/exported tokens. Also signs API tokens.",
    "COUCHDB_SECRET":
        "CouchDB single-node erlang cookie + session secret (obsidian-livesync); "
        "rotation invalidates active sessions and can orphan the on-disk shards. "
        "Set once at first deploy and escrow.",
    # ── Nextcloud Talk HPB — shared with an out-of-band UI ─────────────────────
    "NC_HPB_SHARED_SECRET":
        "manually entered in the Nextcloud Talk admin UI; rotation requires "
        "synchronously updating the value in Nextcloud and restarting Talk.",
    "NC_HPB_HASH_KEY":
        "HMAC-SHA256 key shared between spreed-signaling and Nextcloud Talk; "
        "rotation requires the same Talk admin-UI re-paste.",
    "NC_HPB_BLOCK_KEY":
        "AES-256 key for spreed-signaling block-cipher operations; rotation "
        "requires the Talk admin-UI re-paste.",
    # ── External identity / SSO ────────────────────────────────────────────────
    "AUTHENTIK_BOOTSTRAP_TOKEN":
        "first-run bootstrap superuser token. By design it is REVOKED after the "
        "first successful set-auth run; once revoked it MUST NOT be regenerated "
        "(re-creating a long-lived superuser API token is a structural regression). "
        "Use a scoped service-account token for subsequent automation.",
    # ── Backup encryption (catastrophic if lost) ───────────────────────────────
    "RESTIC_PASSWORD":
        "encrypts the Restic backup repository. Rotation requires re-keying the "
        "repository (restic key add/remove); losing it bricks every backup. "
        "Escrow is mandatory.",
    "RESTIC_REPOSITORY":
        "Restic repository URL is part of the backup identity; changing it "
        "without re-initializing creates an orphan backup repo. Use config-as-code "
        "to move repos, not in-place edit.",
}


# ── Guard ─────────────────────────────────────────────────────────────────────

def assert_immutable(key: str, current: str, new: str) -> None:
    """Raise ValueError if *key* is immutable and *current* would change.

    Rules:
      - Empty *current* → first-run population; any write is allowed.
      - *current* == *new* → idempotent re-write; no-op.
      - Key not in IMMUTABLE_KEYS → passthrough; no check.
      - Otherwise → raise ValueError with the human-readable reason and a
        pointer to the rotation runbook.

    There is intentionally no ``--force`` flag. A deliberate rotation is a
    stopped-stack runbook: stop the stack, escrow the old value, follow the
    per-key rotation procedure — never an in-place .env edit.
    """
    if key not in IMMUTABLE_KEYS:
        return
    if not current:
        return
    if current == new:
        return
    raise ValueError(
        f"{key} is immutable after first deploy: {IMMUTABLE_KEYS[key]} "
        f"To rotate intentionally, stop the stack, escrow the old value, and "
        f"follow the per-key rotation runbook — do not edit .env directly."
    )


def is_immutable(key: str) -> bool:
    """Return True if *key* is registered as immutable-after-first-deploy."""
    return key in IMMUTABLE_KEYS
