# Entra Inline-Groups Live E2E Reproduction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reproduce the four use cases of `docs/plans/entra-v2-inline-groups-200-test.md` as automated live-gateway tests that run against a REAL Microsoft Entra tenant — real v2 end-user tokens, real Entra JWKS/issuer, and (for overage) real Microsoft Graph — instead of mocks, executed against the standard `testing-up` docker stack.

**Architecture:** The tests run against the compose testing gateway (nginx `:8080`), started through a new override file `docker-compose.entra.yml` + `make testing-up-entra` that switches the gateway to trust mode (`JWT_TRUST_MODE=jwt-trust`, `SSO_API_TOKEN_AUTH_ENABLED=true`, `JWT_TRUST_OVERAGE_POLICY=graph_lookup`, `JWT_TRUST_REVOCATION_CLAIM=uti`, `JWT_CLAIM_USER_ID=oid`, `SSO_ENABLED=true`) — following the `docker-compose.sso.yml` override precedent so non-Entra compose usage is untouched. Entra identity is fully real: the test sources a live v2 token (file or ROPC acquisition), seeds the SSO provider trust root from the token's own `iss`/`aud` (JWKS verified against login.microsoftonline.com over public CAs — no `SSL_CERT_FILE` needed), and maps the token's real group GUID to a ContextForge team. The only local component is the in-process stub A2A agent (the manual test also used a local dummy agent), bound to `0.0.0.0` and addressed by the gateway container as `host.docker.internal:<port>`. UC4 uses the real Graph endpoint with the app registration's client credentials seeded onto the provider record; it self-skips with an actionable reason when the tenant lacks overage prerequisites (the case the manual test could not run).

**Tech Stack:** docker compose (override file + make target), pytest + httpx (existing dev deps), in-process uvicorn stub A2A agent (existing harness), Microsoft Entra v2 token endpoint (plain `httpx` ROPC — no new dependency), Microsoft Graph v1.0.

**Spec:** `docs/plans/entra-v2-inline-groups-200-test.md` (the manual test being reproduced).

## Coverage Verdict (why these tasks)

| Use case | Existing coverage | Gap this plan closes |
|---|---|---|
| UC1 mapped developer → invoke 200 | `test_trust_mode_external_ingress_e2e.py::mapped_user_invokes_agent` (local stand-in issuer, status-only assertion) | Real-Entra version + echo round-trip proof (message text reaches the downstream agent) |
| UC2 mapping repointed to other team → 404, no downstream call | Unit: `test_visibility_gate.py::test_team_visibility_isolation`; live: only a nonexistent-agent-name 404 | Live mapping `PUT` → same real token → 404 for a real-but-out-of-team agent + stub-agent never called |
| UC3 viewer role → list/read 200 + invoke 403 | Unit: `test_trust_role_merge.py` viewer deny, `test_internal_a2a_endpoints.py` 403 | Live mapping `PUT` to `cf_role=viewer` → all three HTTP observations with one real token |
| UC4 overage + `graph_lookup` → 200 | Unit only (`test_entra_graph_client.py`, mocked Graph) | Live: real overage token + real Graph resolution → invoke 200; self-skips when tenant lacks prerequisites |

Out of scope (doc "Potential Future Tests" items 2, 3, 5–8 unless already unit-covered): auth deny matrix, group lifecycle/cache grant-revoke sequencing, deployment parity, DB upgrade, app-only token live tests, CF admin tests.

## Global Constraints

- **Live Entra, no mocks** for anything Entra-related (issuer, JWKS, tokens, Graph). The only local stand-in is the downstream stub A2A agent — exactly like the manual test's local dummy agent.
- **The `testing-up` environment is assumed available.** All compose additions go through the new override file `docker-compose.entra.yml` and `make testing-up-entra`; the base `docker-compose.yml` gateway env stays untouched except where a line already exists commented for this purpose. Existing suites that run db-mode expectations keep working: they self-skip unless the pytest process env says `JWT_TRUST_MODE=jwt-trust` (see `test_trust_mode_rbac.py` skip gate).
- **Never log token material.** Assertion messages carry status codes and short body excerpts only (existing convention, see ingress module docstring). Token values live only in fixture-local variables and the `Authorization` header.
- **Secrets never committed.** Entra client secrets, test-account passwords, and acquired tokens come from env vars or untracked files (`.env` / `ENTRA_*`). Compose secrets already flow from `.env` via `make init-secrets-patch-env` (strong values enforced).
- **Self-skip, never fail, when Entra prerequisites are absent** (pattern: `test_trust_mode_entra_barrier.py`). A developer running the suite without Entra credentials sees SKIPPED with the exact env that would enable the test.
- Sign commits (`git commit -s`); Conventional Commits; ASD-STE100 prose.
- Python ≥ 3.12, type hints, Ruff line length 200, interrogate 100% docstring coverage on new modules.
- New work lands as ONE follow-on branch on top of the current stack leaf `feat/6756-app-only-graph-lookup`, created with `gh stack add test-entra-inline-groups-live-e2e` (run from the leaf worktree; non-interactive gh-stack rules: always named args, `--auto` on submit, `--json` on view).

---

### Task 1: Extract shared trust-mode seeding helpers

**Files:**
- Create: `tests/live_gateway/helpers/trust_mode_seed.py`
- Modify: `tests/live_gateway/test_trust_mode_external_ingress_e2e.py` (replace local helper definitions with imports; tests unchanged)
- Test: existing module re-run (Task 7 verification)

**Interfaces:**
- Consumes: `tests/helpers/auth.make_test_jwt`, `helpers/mcp_test_helpers.{ADMIN_EMAIL, BASE_URL, JWT_SECRET}`
- Produces (all parameterized; used by Task 5):
  - `admin_headers() -> dict[str, str]`
  - `seed_team(client: httpx.Client, name: str, description: str) -> str` (returns team id; reuses existing row by name on re-run)
  - `seed_provider(client: httpx.Client, provider_id: str, issuer: str, audience: str, *, token_url: str | None = None, client_id: str | None = None, client_secret: str | None = None) -> None` (delete-first by id; defaults match the current local-issuer payload)
  - `seed_agent(client: httpx.Client, name: str, team_id: str, endpoint_url: str, description: str) -> None` (tolerates 409)
  - `seed_mapping(client: httpx.Client, issuer: str, tenant: str | None, external_group_id: str, cf_team_id: str, cf_role: str) -> str` (returns mapping id; tolerates 409 by listing `(issuer, tenant, group)` and returning the existing row's id)
  - `update_mapping(client: httpx.Client, mapping_id: str, *, cf_team_id: str | None = None, cf_role: str | None = None) -> httpx.Response`

- [ ] **Step 1: Create `tests/live_gateway/helpers/trust_mode_seed.py`** with the five functions above, moving the bodies verbatim from `test_trust_mode_external_ingress_e2e.py:123-231` and replacing the module constants (`TEAM_NAME`, `AGENT_NAME`, `PROVIDER_ID`, `API_AUDIENCE`, `MAPPED_GROUP`) with parameters. Keep the idempotency behaviors (team reuse-by-name listing; provider delete-first; agent 409-tolerant; mapping 409 → list-and-return-id). Add `update_mapping` (new; `PUT {BASE_URL}/admin/external-group-mappings/{mapping_id}` with only the provided fields — mirrors the manual doc §8.2/§9.1).

```python
"""Shared seeding helpers for live trust-mode gateway tests.

Every function targets the running gateway at ``BASE_URL`` through the
admin API with a gateway-signed platform-admin JWT. Seeding is
idempotent: re-runs against a reused database reuse existing rows.
"""

# Future
from __future__ import annotations

# Standard
from typing import Optional

# Third-Party
import httpx

# Local
from tests.helpers.auth import make_test_jwt

from .mcp_test_helpers import ADMIN_EMAIL, BASE_URL, JWT_SECRET


def admin_headers() -> dict[str, str]:
    """Gateway-signed platform-admin headers for seeding (shared test secret).

    token_use="session" gives DB-authoritative team resolution: the platform
    admin resolves to the admin bypass (token_teams=None), whereas a
    claim-less token would resolve token_teams=[] and the public-only
    semantics would suppress admin bypass on the admin APIs.
    """
    token = make_test_jwt(ADMIN_EMAIL, is_admin=True, secret=JWT_SECRET, token_use="session")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def seed_team(client: httpx.Client, name: str, description: str) -> str:
    """Create (or reuse) team ``name``; return its team ID."""
    response = client.post(f"{BASE_URL}/teams/", json={"name": name, "description": description})
    if response.status_code not in (200, 201):
        listing = client.get(f"{BASE_URL}/teams/", params={"include_inactive": "false"})
        assert listing.status_code == 200, f"team seed failed: {response.status_code} {response.text[:200]}; listing failed: {listing.status_code}"
        body = listing.json()
        teams = body.get("teams", body) if isinstance(body, dict) else body
        for team in teams:
            if isinstance(team, dict) and team.get("name") == name:
                return team["id"]
        raise AssertionError(f"team seed failed: {response.status_code} {response.text[:200]}")
    return response.json()["id"]


def seed_provider(
    client: httpx.Client,
    provider_id: str,
    issuer: str,
    audience: str,
    *,
    token_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> None:
    """Create the SSOProvider trust root for ``issuer`` (idempotent)."""
    client.delete(f"{BASE_URL}/auth/sso/admin/providers/{provider_id}")
    payload = {
        "id": provider_id,
        "name": provider_id,
        "display_name": provider_id,
        "provider_type": "oidc",
        "client_id": client_id or "local-oidc-test-client",
        "client_secret": client_secret or "local-oidc-test-secret",  # pragma: allowlist secret
        "authorization_url": f"{issuer}/authorize",
        "token_url": token_url or f"{issuer}/token",
        "userinfo_url": f"{issuer}/userinfo",
        "issuer": issuer,
        "trusted_for_api_auth": True,
        "api_audience": audience,
    }
    response = client.post(f"{BASE_URL}/auth/sso/admin/providers", json=payload)
    assert response.status_code in (200, 201), f"provider seed failed: {response.status_code} {response.text[:200]}"


def seed_agent(client: httpx.Client, name: str, team_id: str, endpoint_url: str, description: str) -> None:
    """Register a team-visible A2A agent (idempotent)."""
    payload = {
        "agent": {
            "name": name,
            "description": description,
            "endpoint_url": endpoint_url,
            "agent_type": "generic",
        },
        "team_id": team_id,
        "visibility": "team",
    }
    response = client.post(f"{BASE_URL}/a2a/", json=payload)
    assert response.status_code in (200, 201, 409), f"agent seed failed: {response.status_code} {response.text[:200]}"


def seed_mapping(client: httpx.Client, issuer: str, tenant: Optional[str], external_group_id: str, cf_team_id: str, cf_role: str) -> str:
    """Map external group -> team + role; return the mapping ID (idempotent)."""
    payload = {
        "issuer": issuer,
        "tenant": tenant,
        "external_group_id": external_group_id,
        "cf_team_id": cf_team_id,
        "cf_role": cf_role,
    }
    response = client.post(f"{BASE_URL}/admin/external-group-mappings", json=payload)
    if response.status_code in (200, 201):
        return response.json()["id"]
    if response.status_code == 409:
        listing = client.get(f"{BASE_URL}/admin/external-group-mappings")
        assert listing.status_code == 200, f"mapping listing failed: {listing.status_code} {listing.text[:200]}"
        for row in listing.json():
            if row.get("issuer") == issuer and row.get("external_group_id") == external_group_id and row.get("tenant") == tenant:
                return row["id"]
    raise AssertionError(f"mapping seed failed: {response.status_code} {response.text[:200]}")


def update_mapping(client: httpx.Client, mapping_id: str, *, cf_team_id: Optional[str] = None, cf_role: Optional[str] = None) -> httpx.Response:
    """PUT a partial mapping update (team repoint and/or role change)."""
    payload: dict[str, str] = {}
    if cf_team_id is not None:
        payload["cf_team_id"] = cf_team_id
    if cf_role is not None:
        payload["cf_role"] = cf_role
    return client.put(f"{BASE_URL}/admin/external-group-mappings/{mapping_id}", json=payload)
```

- [ ] **Step 2: Refactor `test_trust_mode_external_ingress_e2e.py`** — delete `_admin_headers`, `_seed_team`, `_seed_provider`, `_seed_agent`, `_seed_mapping` (lines ~123–231) and import from the new helper module; update the `seeded_gateway` fixture call sites (`_seed_team(client)` → `seed_team(client, TEAM_NAME, "T9 ingress matrix team")`, etc.). Do not change the matrix, claims, or assertions.

- [ ] **Step 3: Lint the new module**

Run: `uv tool run ruff check tests/live_gateway/helpers/trust_mode_seed.py tests/live_gateway/test_trust_mode_external_ingress_e2e.py && uv tool run interrogate tests/live_gateway/helpers/trust_mode_seed.py`
Expected: no findings; interrogate 100%.

- [ ] **Step 4: Commit**

```bash
git add tests/live_gateway/helpers/trust_mode_seed.py tests/live_gateway/test_trust_mode_external_ingress_e2e.py
git commit -s -m "refactor(tests): extract trust-mode seeding helpers for live suites"
```

---

### Task 2: Stub agent echo, invocation recording, container reachability

**Files:**
- Modify: `tests/live_gateway/helpers/local_oidc_issuer.py` (`stub_agent_invoke` ~line 185; stub server startup; fixture namespace ~line 250)

**Interfaces:**
- Produces:
  - Fixture namespace gains `stub_agent_invocations: list[dict]` (append-only; one entry per downstream call: `{"message_text": <str>, "received_at": <float>}`); the stub response now echoes the sent message text so tests can prove the round-trip (UC1) and its absence (UC2/UC3).
  - Fixture namespace gains `stub_agent_port: int` and `stub_agent_url_for_gateway: str` — the stub agent now binds `0.0.0.0` and the gateway-facing URL is `http://{STUB_AGENT_GATEWAY_HOST:-host.docker.internal}:{port}/stub-agent/invoke`, so the compose gateway container can call the host-run stub. The existing `stub_agent_url` (loopback form) is unchanged for the ingress module.

- [ ] **Step 1: Update `stub_agent_invoke`** — record invocations on `app.state.stub_invocations` and echo the message text. The stub keeps completing immediately; only observability changes:

```python
@app.post("/stub-agent/invoke")
async def stub_agent_invoke(request: Request) -> JSONResponse:
    """Stub A2A agent: complete every JSON-RPC invocation immediately."""
    try:
        body = await request.json()
    except Exception:  # pylint: disable=broad-except
        body = {}
    request_id = body.get("id", 1) if isinstance(body, dict) else 1
    message_text = ""
    if isinstance(body, dict):
        for part in body.get("params", {}).get("message", {}).get("parts", []):
            if isinstance(part, dict) and part.get("text"):
                message_text = str(part["text"])
                break
    request.app.state.stub_invocations.append({"message_text": message_text, "received_at": time.time()})
    result = {
        "id": "task-local-oidc-1",
        "contextId": "ctx-local-oidc-1",
        "status": {"state": "completed"},
        "artifacts": [{"name": "response", "parts": [{"text": f"[Stub Agent] Received your message: '{message_text}'"}]}],
        "history": [],
    }
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})
```

Also initialize the list right after `app = FastAPI(...)`: `app.state.stub_invocations = []` (add `import time` if missing).

- [ ] **Step 2: Bind the stub agent to `0.0.0.0` and expose the gateway-facing URL.** Where the fixture starts the plain-HTTP stub server (currently host `127.0.0.1`), change to host `"0.0.0.0"` (the TLS issuer server keeps `127.0.0.1`). Capture the chosen port and add to the yielded namespace:

```python
stub_gateway_host = os.getenv("STUB_AGENT_GATEWAY_HOST", "host.docker.internal")
# inside the yielded namespace:
#   "stub_agent_port": stub_port,
#   "stub_agent_url_for_gateway": f"http://{stub_gateway_host}:{stub_port}/stub-agent/invoke",
```

Binding to `0.0.0.0` on an ephemeral port is required so the Docker gateway container can reach the host-run stub via `host.docker.internal` (Docker Desktop resolves it natively; Linux needs the `extra_hosts` added in Task 3).

- [ ] **Step 3: Verify the existing ingress module still passes** (operator gateway per its own docstring; the loopback `stub_agent_url` and TLS issuer are unchanged).

- [ ] **Step 4: Commit**

```bash
git add tests/live_gateway/helpers/local_oidc_issuer.py
git commit -s -m "test(harness): echo message text, record stub invocations, bind stub for container access"
```

---

### Task 3: Entra override for the testing stack

**Files:**
- Create: `docker-compose.entra.yml`
- Modify: `Makefile` (new target `testing-up-entra` next to the existing `testing-up`)
- Modify: `charts/` — NOT touched; Helm parity is doc item 5, out of scope.

**Interfaces:**
- Produces: `make testing-up-entra` — the standard `testing-up` stack (nginx `:8080`, gateway, redis, echo agents) with the gateway switched to Entra trust mode. Non-Entra compose usage (`make testing-up`, `docker compose up`, the `sso` profile) is untouched because the base `docker-compose.yml` gateway env is not modified.

- [ ] **Step 1: Write `docker-compose.entra.yml`** (override file, `docker-compose.sso.yml` precedent):

```yaml
# Entra live-testing override for the gateway service.
#
# Apply on top of the base compose file together with the testing
# profile (see `make testing-up-entra`):
#
#   docker compose -f docker-compose.yml -f docker-compose.entra.yml --profile testing up -d
#
# Switches the gateway to external-IdP trust mode with the Entra v2
# claim conventions used by the inline-groups live e2e suite:
#   - user identity from the Entra `oid` claim
#   - revocation keyed on the Entra `uti` claim
#   - group overage resolved through Microsoft Graph (app-only)
# The base compose file stays untouched so db-mode suites and other
# profiles keep their defaults.
services:
  gateway:
    environment:
      - SSO_ENABLED=true
      - JWT_TRUST_MODE=jwt-trust
      - SSO_API_TOKEN_AUTH_ENABLED=true
      - JWT_TRUST_OVERAGE_POLICY=graph_lookup
      - JWT_TRUST_REVOCATION_CLAIM=uti
      - JWT_CLAIM_USER_ID=oid
    extra_hosts:
      # Linux: map host.docker.internal to the host so the gateway can
      # reach the host-run stub A2A agent. Docker Desktop provides this
      # mapping natively; the extra host is harmless there.
      - "host.docker.internal:host-gateway"
```

- [ ] **Step 2: Add the Makefile target** beside `testing-up` (copy its command shape, add the override file):

```makefile
.PHONY: testing-up-entra
testing-up-entra: ## 🧪 Start the testing stack with the gateway in Entra trust mode
    docker compose -f docker-compose.yml -f docker-compose.entra.yml --profile testing up -d
    @echo "Entra trust-mode testing stack up. Gateway: http://localhost:8080"
```

(Adjust the profile list to match the existing `testing-up` target exactly — whatever services it includes, e.g. `--profile testing --profile sso`, replicate minus the sso profile.)

- [ ] **Step 3: Validate the stack**

Run: `make docker-nuke && make testing-up-entra`
Expected: stack healthy; `curl -sS http://127.0.0.1:8080/health` OK; `docker compose -f docker-compose.yml -f docker-compose.entra.yml exec gateway printenv JWT_TRUST_MODE` prints `jwt-trust`.

- [ ] **Step 4: Confirm db-mode suites are unaffected**

Run: `make test-e2e`
Expected: green. Trust-mode live modules self-skip (their skip gate reads the pytest env `JWT_TRUST_MODE`, which `test-e2e` does not set); no db-mode test reads the gateway's env directly.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.entra.yml Makefile
git commit -s -m "feat(testing): add Entra trust-mode override for the testing stack"
```

---

### Task 4: Live-Entra token harness

**Files:**
- Create: `tests/live_gateway/helpers/entra_live.py`

**Interfaces:**
- Produces:
  - `load_entra_token() -> str | None` — env `ENTRA_LIVE_TOKEN_FILE` (a file containing one raw JWT; `ENTRA_LIVE_TOKEN_DIR` with `entra-token-valid-v2.txt` accepted as fallback, mirroring `test_trust_mode_entra_barrier.py`). Returns `None` when absent (caller skips).
  - `acquire_entra_token_ropc() -> str | None` — optional non-interactive acquisition when `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_TEST_USERNAME`, `ENTRA_TEST_PASSWORD` are set; plain `httpx` POST `grant_type=password` to `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `scope` = `ENTRA_TOKEN_SCOPE` or default `"{client_id}/.default openid profile"`. Never logs the password or returned token.
  - `inspect_token(token: str) -> dict` — decodes the payload WITHOUT verification (the gateway verifies via JWKS) and returns `{"issuer", "audience", "tenant_id", "oid", "uti", "groups": [...], "has_overage_marker", "exp"}` (same extraction as the manual doc §1/§4.2).
  - `validate_for_inline_groups(claims: dict) -> list[str]` — returns a list of unmet requirements (empty = usable): `groups` non-empty, no overage marker, not expired, `oid` present, `uti` present.
  - Fixture `entra_inline_token` (session scope) — resolves file-or-ROPC, validates, and `pytest.skip` with the exact missing env when unusable. Yields `(token: str, info: dict)`.

- [ ] **Step 1: Write `tests/live_gateway/helpers/entra_live.py`**

```python
"""Live Microsoft Entra token sourcing for inline-groups e2e tests.

Tokens are NEVER mocked and NEVER logged. Two sourcing modes, first
match wins:

1. ``ENTRA_LIVE_TOKEN_FILE`` (or ``ENTRA_LIVE_TOKEN_DIR`` containing
   ``entra-token-valid-v2.txt``): a pre-acquired v2 end-user token, as
   produced interactively for the manual test run.
2. ROPC acquisition when ``ENTRA_TENANT_ID``, ``ENTRA_CLIENT_ID``,
   ``ENTRA_TEST_USERNAME`` and ``ENTRA_TEST_PASSWORD`` are set. ROPC
   requires a dedicated test account without interactive MFA; tenants
   that block ROPC should use mode 1.

The gateway performs the real verification against Entra JWKS; the
payload decode here is for extracting seeding values only.
"""

# Future
from __future__ import annotations

# Standard
import base64
import json
import os
import time
from typing import Any, Optional

# Third-Party
import httpx
import pytest

DEFAULT_TOKEN_FILENAME = "entra-token-valid-v2.txt"


def _decode_payload(token: str) -> dict[str, Any]:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def inspect_token(token: str) -> dict[str, Any]:
    """Extract non-secret seeding values from a v2 token payload."""
    claims = _decode_payload(token)
    groups = claims.get("groups", [])
    audience = claims.get("aud")
    if isinstance(audience, list):
        audience = audience[0] if audience else None
    return {
        "issuer": claims.get("iss"),
        "audience": audience,
        "tenant_id": claims.get("tid"),
        "oid": claims.get("oid"),
        "uti": claims.get("uti"),
        "groups": [str(group) for group in groups] if isinstance(groups, list) else [],
        "has_overage_marker": bool(claims.get("hasgroups") or claims.get("_claim_names")),
        "exp": claims.get("exp"),
    }


def validate_for_inline_groups(info: dict[str, Any]) -> list[str]:
    """Return unmet requirements for the inline-groups use cases."""
    problems: list[str] = []
    if not info["groups"]:
        problems.append("token carries no inline groups claim")
    if info["has_overage_marker"]:
        problems.append("token carries a group-overage marker (need a non-overage user token for UC1-3)")
    if not isinstance(info["exp"], int) or info["exp"] <= int(time.time()):
        problems.append("token is expired")
    if not info["oid"]:
        problems.append("token lacks oid (JWT_CLAIM_USER_ID target)")
    if not info["uti"]:
        problems.append("token lacks uti (JWT_TRUST_REVOCATION_CLAIM target)")
    return problems


def load_entra_token() -> Optional[str]:
    """Load a pre-acquired token from file, if configured."""
    path = os.getenv("ENTRA_LIVE_TOKEN_FILE")
    if not path:
        directory = os.getenv("ENTRA_LIVE_TOKEN_DIR")
        if directory:
            path = os.path.join(directory, DEFAULT_TOKEN_FILENAME)
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def acquire_entra_token_ropc() -> Optional[str]:
    """Acquire a token via ROPC when all credentials are configured."""
    tenant = os.getenv("ENTRA_TENANT_ID")
    client_id = os.getenv("ENTRA_CLIENT_ID")
    username = os.getenv("ENTRA_TEST_USERNAME")
    password = os.getenv("ENTRA_TEST_PASSWORD")
    if not (tenant and client_id and username and password):
        return None
    response = httpx.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": os.getenv("ENTRA_TOKEN_SCOPE", f"{client_id}/.default openid profile"),
        },
        timeout=30,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Entra ROPC acquisition failed with HTTP {response.status_code}; body carried no logged secrets")
    return response.json()["access_token"]


@pytest.fixture(scope="session")
def entra_inline_token() -> Any:
    """Yield (token, info) from a REAL Entra v2 token; skip when unavailable.

    Skip reasons name the exact environment variables that enable the
    test; a skipped run never fails the suite.
    """
    token = load_entra_token() or acquire_entra_token_ropc()
    if not token:
        pytest.skip(
            "live Entra token not configured: set ENTRA_LIVE_TOKEN_FILE (or "
            "ENTRA_LIVE_TOKEN_DIR/entra-token-valid-v2.txt), or ROPC env "
            "ENTRA_TENANT_ID + ENTRA_CLIENT_ID + ENTRA_TEST_USERNAME + ENTRA_TEST_PASSWORD"
        )
    info = inspect_token(token)
    problems = validate_for_inline_groups(info)
    if problems:
        pytest.skip(f"live Entra token unusable for inline-groups tests: {'; '.join(problems)}")
    yield token, info
```

- [ ] **Step 2: Lint + docstring coverage**

Run: `uv tool run ruff check tests/live_gateway/helpers/entra_live.py && uv tool run interrogate tests/live_gateway/helpers/entra_live.py`
Expected: clean; 100%.

- [ ] **Step 3: Sanity-check the decoder against an existing local token file** (developer machine only; file is untracked):

Run: `ENTRA_LIVE_TOKEN_FILE=./entra-token-valid-v2.txt uv run python -c "from tests.live_gateway.helpers.entra_live import load_entra_token, inspect_token, validate_for_inline_groups; t=load_entra_token(); i=inspect_token(t) if t else None; print('loaded' if t else 'none'); print({k: (v if k != 'groups' else len(v)) for k, v in i.items()} if i else ''); print(validate_for_inline_groups(i) if i else '')"`
Expected: `loaded`, issuer `https://login.microsoftonline.com/<tid>/v2.0`, groups count > 0, `[]` problems (if the local token is a valid non-overage v2 token; a stale/expired token prints exactly which problem — refresh before the live run).

- [ ] **Step 4: Commit**

```bash
git add tests/live_gateway/helpers/entra_live.py
git commit -s -m "test(harness): add live Entra token sourcing for inline-groups e2e"
```

---

### Task 5: Live module — UC1, UC2, UC3 (against the testing stack)

**Files:**
- Create: `tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py`

**Interfaces:**
- Consumes: `entra_inline_token`, `local_oidc_issuer` (stub agent only, via `stub_agent_url_for_gateway` + `stub_agent_invocations`), `trust_mode_seed.{admin_headers, seed_team, seed_provider, seed_agent, seed_mapping, update_mapping}`, `mcp_test_helpers.{BASE_URL, JWT_SECRET, skip_no_gateway}`
- Produces: three tests reproducing manual UC1–UC3 verbatim against `make testing-up-entra`.

- [ ] **Step 1: Write the module.** Module docstring carries the runbook:

```text
Runbook (from the repo root):

    # 1. Start the Entra trust-mode testing stack (assumes .env exists
    #    with the strong secrets from make init-secrets-patch-env):
    make docker-nuke && make testing-up-entra

    # 2. Acquire a fresh Entra v2 end-user token with inline groups
    #    (non-overage user; see docs/plans/entra-v2-inline-groups-200-test.md §0-§1)
    #    and save it to an untracked file.

    # 3. Run (JWT_SECRET_KEY must match the gateway's .env value):
    JWT_TRUST_MODE=jwt-trust \
    JWT_SECRET_KEY="$(grep -E '^JWT_SECRET_KEY=' .env | cut -d= -f2-)" \
    ENTRA_LIVE_TOKEN_FILE=/path/to/entra-token-valid-v2.txt \
        uv run pytest tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py -v

The gateway is the compose testing gateway behind nginx :8080
(MCP_CLI_BASE_URL default). JWKS verification hits the real Entra
issuer over public CAs. The downstream stub A2A agent runs in this
pytest process and is reached by the gateway container through
host.docker.internal.
```

Core module content:

```python
AGENT_NAME = "Entra-Live-Agent"
PROVIDER_ID = "entra-live-trust-root"
NO_AGENT_TEAM_NAME = "Entra Live No-Agent Team"

pytestmark = [pytest.mark.e2e, skip_no_gateway]
pytestmark.append(pytest.mark.skipif(os.getenv("JWT_TRUST_MODE", "db") != "jwt-trust", reason="requires the stack started with JWT_TRUST_MODE=jwt-trust (make testing-up-entra)"))


def _invoke(agent_name: str, token: str, message_text: str) -> httpx.Response:
    return httpx.post(
        f"{BASE_URL}/a2a/{agent_name}/invoke",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "parameters": {
                "message": {
                    "messageId": f"msg-{uuid.uuid4().hex[:8]}",
                    "role": "user",
                    "parts": [{"text": message_text}],
                }
            },
            "interaction_type": "query",
        },
        timeout=30,
    )


@pytest.fixture(scope="module")
def entra_seeded(entra_inline_token, local_oidc_issuer):
    """Seed trust root, team, stub-backed agent, and mapping from the REAL token.

    Returns a dict with the token, seeding values, mapping id, and the
    stub-agent invocation log. Teardown deletes the mapping so later runs
    and other suites never inherit a stale team/role for this group.
    """
    token, info = entra_inline_token
    with httpx.Client(headers=admin_headers(), timeout=30) as client:
        team_id = seed_team(client, "Entra Live Agent Team", "Live Entra inline-groups e2e")
        no_agent_team_id = seed_team(client, NO_AGENT_TEAM_NAME, "Mapped team without agent access")
        seed_provider(client, PROVIDER_ID, info["issuer"], info["audience"])
        seed_agent(client, AGENT_NAME, team_id, local_oidc_issuer.stub_agent_url_for_gateway, "Live Entra stub-backed agent")
        mapping_id = seed_mapping(client, info["issuer"], info["tenant_id"], info["groups"][0], team_id, "developer")
    yield {
        "token": token,
        "info": info,
        "team_id": team_id,
        "no_agent_team_id": no_agent_team_id,
        "mapping_id": mapping_id,
        "stub_invocations": local_oidc_issuer.stub_agent_invocations,
    }
    with httpx.Client(headers=admin_headers(), timeout=30) as client:
        client.delete(f"{BASE_URL}/admin/external-group-mappings/{mapping_id}")
```

Test 1 — UC1 (echo round-trip + downstream proof):

```python
def test_uc1_mapped_developer_invokes_agent(entra_seeded):
    """UC1: mapped group + developer -> 200 and the message reaches the agent."""
    before = len(entra_seeded["stub_invocations"])
    message = "Hello from live Entra inline-groups e2e"
    response = _invoke(AGENT_NAME, entra_seeded["token"], message)
    assert response.status_code == 200, f"UC1 expected 200, got {response.status_code}: {response.text[:200]}"
    artifacts = response.json()["result"]["artifacts"]
    echoed = artifacts[0]["parts"][0]["text"] if artifacts and artifacts[0].get("parts") else ""
    assert message in echoed, f"UC1 echo round-trip failed: {echoed[:200]}"
    assert len(entra_seeded["stub_invocations"]) == before + 1, "UC1: downstream stub agent was not called exactly once"
```

Test 2 — UC2 (mapping repoint → 404, no downstream call):

```python
def test_uc2_repointed_team_hides_agent_with_404(entra_seeded):
    """UC2: same token, mapping moved to a team without the agent -> 404, agent never called."""
    with httpx.Client(headers=admin_headers(), timeout=30) as client:
        update = update_mapping(client, entra_seeded["mapping_id"], cf_team_id=entra_seeded["no_agent_team_id"])
        assert update.status_code == 200, f"mapping repoint failed: {update.status_code} {update.text[:200]}"
        body = update.json()
        assert body["cf_team_id"] == entra_seeded["no_agent_team_id"], "mapping PUT did not persist the new team"
        assert body["cf_role"] == "developer", "mapping PUT must retain the role absent from the payload"
    before = len(entra_seeded["stub_invocations"])
    denied_text = "This live request must not reach the stub agent"
    response = _invoke(AGENT_NAME, entra_seeded["token"], denied_text)
    assert response.status_code == 404, f"UC2 expected 404, got {response.status_code}: {response.text[:200]}"
    assert "not found" in response.text.lower(), f"UC2 body must be the agent-not-found detail: {response.text[:200]}"
    assert len(entra_seeded["stub_invocations"]) == before, "UC2 LEAK: denied message reached the downstream agent"
```

Test 3 — UC3 (viewer: list/read 200, invoke 403, no downstream call):

```python
def test_uc3_viewer_sees_but_cannot_invoke(entra_seeded):
    """UC3: mapping repointed to viewer -> list 200, read 200, invoke 403, agent never called."""
    headers = {"Authorization": f"Bearer {entra_seeded['token']}", "Content-Type": "application/json"}
    with httpx.Client(headers=admin_headers(), timeout=30) as client:
        update = update_mapping(client, entra_seeded["mapping_id"], cf_team_id=entra_seeded["team_id"], cf_role="viewer")
        assert update.status_code == 200, f"mapping role change failed: {update.status_code} {update.text[:200]}"
        body = update.json()
        assert body["cf_team_id"] == entra_seeded["team_id"] and body["cf_role"] == "viewer", "mapping PUT did not persist team+viewer"
    listing = httpx.get(f"{BASE_URL}/a2a/", headers=headers, timeout=30)
    assert listing.status_code == 200, f"UC3 list expected 200, got {listing.status_code}"
    agents = listing.json() if isinstance(listing.json(), list) else listing.json().get("agents", [])
    agent_row = next((row for row in agents if row.get("name") == AGENT_NAME), None)
    assert agent_row is not None, "UC3: viewer cannot see the team-visible agent in the list"
    read = httpx.get(f"{BASE_URL}/a2a/{agent_row['id']}", headers=headers, timeout=30)
    assert read.status_code == 200, f"UC3 read expected 200, got {read.status_code}"
    before = len(entra_seeded["stub_invocations"])
    denied_text = "This live viewer request must not reach the stub agent"
    response = _invoke(AGENT_NAME, entra_seeded["token"], denied_text)
    assert response.status_code == 403, f"UC3 expected 403, got {response.status_code}: {response.text[:200]}"
    assert "access denied" in response.text.lower(), f"UC3 body must be the RBAC deny detail: {response.text[:200]}"
    assert len(entra_seeded["stub_invocations"]) == before, "UC3 LEAK: viewer message reached the downstream agent"
```

Test order matters (module-scope fixture state: UC2 repoints, UC3 restores). Rely on pytest's definition-order execution within the module. Teardown deletes the mapping, so no restore step is needed.

- [ ] **Step 2: Run the module end-to-end per the runbook** (fresh token; `x-correlation-id` in any failure output aids log correlation, mirroring the manual doc).
Expected: 3 passed (or SKIPPED with the exact missing env when no token is configured).

- [ ] **Step 3: Verify skip path in a bare environment**

Run: `env -u ENTRA_LIVE_TOKEN_FILE -u ENTRA_LIVE_TOKEN_DIR -u ENTRA_TENANT_ID JWT_TRUST_MODE=jwt-trust JWT_SECRET_KEY="$(grep -E '^JWT_SECRET_KEY=' .env | cut -d= -f2-)" uv run pytest tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py -v`
Expected: 3 skipped, 0 failed.

- [ ] **Step 4: Commit**

```bash
git add tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py
git commit -s -m "test(e2e): reproduce Entra inline-groups access cases 1-3 against a live tenant"
```

---

### Task 6: Live UC4 — overage token + real Graph resolution

**Files:**
- Modify: `tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py` (append UC4)

**Interfaces:**
- Consumes: `entra_live.inspect_token`, a second fixture sourcing an overage token, `trust_mode_seed` helpers, gateway env `JWT_TRUST_OVERAGE_POLICY=graph_lookup` (already set by `make testing-up-entra` from Task 3).
- Prerequisites (all env-provided; skip when absent):
  - `ENTRA_OVERAGE_TOKEN_FILE` — a v2 token for a user in >200 groups (overage marker present). The doc author's regular account qualifies; the admin account does not.
  - `ENTRA_GRAPH_CLIENT_ID` + `ENTRA_GRAPH_CLIENT_SECRET` (fall back to `ENTRA_CLIENT_ID`/`ENTRA_CLIENT_SECRET`) — an App Registration with admin-consented Microsoft Graph application permissions `GroupMember.Read.All` (or `Directory.Read.All`) for client-credentials resolution. These are seeded onto the SSO provider record so the gateway itself performs the real Graph call.
  - Optional `ENTRA_OVERAGE_MAPPED_GROUP` — the group GUID Graph will resolve, for overage tokens that carry NO inline groups at all.

- [ ] **Step 1: Add the overage fixture + test**

```python
@pytest.fixture(scope="module")
def entra_overage_token():
    """Yield (token, info) from a REAL overage-marked Entra token; skip when absent."""
    path = os.getenv("ENTRA_OVERAGE_TOKEN_FILE")
    if not path or not os.path.isfile(path):
        pytest.skip(
            "UC4 needs a real overage token: set ENTRA_OVERAGE_TOKEN_FILE to a v2 token "
            "for a user in more than 200 groups (group-overage marker present)"
        )
    with open(path, encoding="utf-8") as handle:
        token = handle.read().strip()
    info = inspect_token(token)
    if not info["has_overage_marker"]:
        pytest.skip("UC4 token has no overage marker; need a member of >200 groups")
    if not isinstance(info["exp"], int) or info["exp"] <= int(time.time()):
        pytest.skip("UC4 token is expired; re-acquire before running")
    yield token, info


def test_uc4_overage_resolved_via_graph_allows_invoke(entra_overage_token, local_oidc_issuer):
    """UC4: overage marker + graph_lookup policy -> real Graph resolves groups -> 200.

    The gateway (started via make testing-up-entra) performs the app-only
    Graph resolution itself: the provider record below carries real
    Graph-capable client credentials, and the group mapped to the agent
    team is the overage user's group resolved BY GRAPH (not present
    inline).
    """
    if os.getenv("JWT_TRUST_OVERAGE_POLICY", "fail_closed") != "graph_lookup":
        pytest.skip("UC4 requires the gateway started with JWT_TRUST_OVERAGE_POLICY=graph_lookup (make testing-up-entra)")
    graph_client_id = os.getenv("ENTRA_GRAPH_CLIENT_ID") or os.getenv("ENTRA_CLIENT_ID")
    graph_client_secret = os.getenv("ENTRA_GRAPH_CLIENT_SECRET") or os.getenv("ENTRA_CLIENT_SECRET")
    if not (graph_client_id and graph_client_secret):
        pytest.skip(
            "UC4 needs Graph-capable app credentials (admin-consented GroupMember.Read.All): "
            "set ENTRA_GRAPH_CLIENT_ID + ENTRA_GRAPH_CLIENT_SECRET"
        )
    token, info = entra_overage_token
    overage_group = info["groups"][0] if info["groups"] else os.environ["ENTRA_OVERAGE_MAPPED_GROUP"]
    with httpx.Client(headers=admin_headers(), timeout=30) as client:
        team_id = seed_team(client, "Entra Live Overage Team", "Live Entra overage graph_lookup e2e")
        seed_provider(
            client,
            "entra-live-overage-root",
            info["issuer"],
            info["audience"],
            token_url=f"https://login.microsoftonline.com/{info['tenant_id']}/oauth2/v2.0/token",
            client_id=graph_client_id,
            client_secret=graph_client_secret,
        )
        seed_agent(client, "Entra-Live-Overage-Agent", team_id, local_oidc_issuer.stub_agent_url_for_gateway, "Live Entra overage agent")
        mapping_id = seed_mapping(client, info["issuer"], info["tenant_id"], overage_group, team_id, "developer")
    try:
        message = "Hello from live Entra overage graph_lookup e2e"
        response = _invoke("Entra-Live-Overage-Agent", token, message)
        assert response.status_code == 200, f"UC4 expected 200, got {response.status_code}: {response.text[:200]}"
        artifacts = response.json()["result"]["artifacts"]
        echoed = artifacts[0]["parts"][0]["text"] if artifacts and artifacts[0].get("parts") else ""
        assert message in echoed, f"UC4 echo round-trip failed: {echoed[:200]}"
    finally:
        with httpx.Client(headers=admin_headers(), timeout=30) as client:
            client.delete(f"{BASE_URL}/admin/external-group-mappings/{mapping_id}")
```

Notes baked into the test docstring and runbook: when the overage token carries no inline groups, `ENTRA_OVERAGE_MAPPED_GROUP` must name a group the overage user belongs to — Graph resolves membership and the mapping turns it into the agent team + developer role. The gateway's real Graph call must succeed, so the App Registration needs the consented permission; a tenant that cannot provide it keeps this test SKIPPED — this is the honest reproduction of "not testable here", never a mock.

- [ ] **Step 2: Run with prerequisites present** (overage user token + consented app).
Expected: 4 passed. If the Graph resolution fails, the response is 401 with the actionable overage detail — correlate via `x-correlation-id` in gateway logs before changing anything.

- [ ] **Step 3: Run without prerequisites.**
Expected: UC4 SKIPPED with the actionable env names; UC1–3 unaffected.

- [ ] **Step 4: Commit**

```bash
git add tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py
git commit -s -m "test(e2e): reproduce Entra overage graph_lookup use case against live Graph"
```

---

### Task 7: Stack integration + validation gate

**Files:** none new (branch/PR plumbing + verification).

- [ ] **Step 1: Create the follow-on branch on top of the leaf**

Run (from this worktree, currently on `feat/6756-app-only-graph-lookup`, tracked files clean):
```bash
gh stack add test-entra-inline-groups-live-e2e
```
(If Tasks 1–6 were committed directly on the leaf by mistake, instead create the branch and cherry-pick/reset so the leaf stays pristine; the five commits belong on the new branch.)

- [ ] **Step 2: Hygiene chain on changed files**

Run: `make pre-commit && make ruff bandit interrogate pylint verify`
Expected: green (interrogate 100% on the two new helper modules and the new test module).

- [ ] **Step 3: Full unit suite (no Entra needed — everything self-skips)**

Run: `make test`
Expected: green; the new live module collects and skips.

- [ ] **Step 4: Live verification** — `make docker-nuke && make testing-up-entra`, then per the Task 5 runbook: fresh non-overage token → 3 passed (+1 with overage prerequisites); then re-run the refactored ingress module on its own operator gateway (its docstring env) to prove the Task 1 refactor and Task 2 harness changes are behavior-neutral.

- [ ] **Step 5: Standard stack regression**

Run: `make docker-nuke && make docker-prod-rust testing-up RUST_MCP_MODE= && make test-e2e && make test-mcp-protocol-e2e test-mcp-rbac && make detect-secrets-scan`
Expected: all green (proves the override file and Makefile target did not disturb the default stacks; no secrets added — the override contains no credentials).

- [ ] **Step 6: Push and open the PR**

```bash
gh stack submit --auto
```
Expected: `Created PR #<n> for test-entra-inline-groups-live-e2e (base: feat/6756-app-only-graph-lookup)`. Do not merge; the stack merges bottom-up.

---

## Self-Review

- **Spec coverage:** UC1 → Task 5 test 1 (200 + echo + stub called once); UC2 → Task 5 test 2 (404 + retained role + no downstream call); UC3 → Task 5 test 3 (list/read 200 + invoke 403 + no downstream call); UC4 → Task 6 (overage + graph_lookup + 200, live Graph, skip-when-absent). Doc §0–§6 setup → Tasks 1+4+5 fixtures and Task 3 stack; §7–§9 → Tasks 5–6. Manual-only artifacts (correlation-id log correlation) are covered by failure-path assertions carrying body excerpts.
- **No placeholders:** every code step carries complete code; the only operator inputs are secrets by design (env/files), named exactly. The Makefile target's command shape must be copied from the existing `testing-up` target (verify profile flags verbatim during implementation).
- **Type consistency:** `seed_mapping` returns `str` (mapping id) used by `update_mapping(client, mapping_id, ...)`; fixture yields `(token, info)` consumed as `token, info = entra_inline_token`; `stub_agent_invocations` list shared by reference from fixture namespace to `entra_seeded`; `stub_agent_url_for_gateway` produced by Task 2, consumed by Tasks 5–6.
- **Live-not-mock directive:** the only local component is the downstream stub A2A agent (the manual test also used a local dummy agent); issuer, JWKS, tokens, tenant, and Graph are real Entra services.
- **Testing-stack directive:** the gateway under test comes from `make testing-up-entra` (Task 3); base compose files and db-mode suites are untouched (verified in Task 3 Step 4 and Task 7 Step 5).
