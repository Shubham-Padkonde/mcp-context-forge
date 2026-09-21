# Entra Trust-Mode Remediation Plan (TDD, in-stack)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every blocking finding from `docs/plans/epic-investigation.md` (and the actionable non-blocking concerns) by editing the existing 25-PR gh-stack in place, earliest branch → latest branch, test-first throughout.

**Architecture:** The stack already contains the trust-mode machinery (claims extraction, group mapping, `VirtualPrincipal`, external JWKS verification); the findings are wiring failures between those pieces. Each task lands a failing test on the PR branch that owns the code, then the fix, then propagates with `gh stack rebase --upstack`. The barrier test added to PR #6746 (`tests/live_gateway/test_trust_mode_entra_barrier.py`) is the anchor: its pinned `401` flips to `403` when Task 9 fixes ingress (no group mapping exists in the barrier scenario), and the full matrix (200/404) is proven by the black-box suite added in the same task.

**Tech Stack:** FastAPI/Pydantic/SQLAlchemy/Alembic, pytest (+ pytest-asyncio, `--with-integration`), gh-stack CLI, httpx, PyJWT/cryptography for local OIDC test issuer.

**Spec:**
- `docs/plans/epic-investigation.md` — findings F1–F9 (blocking), NB1–NB8 (non-blocking), "What Is Still Needed" items 1–10.
- `docs/plans/entra-a2a-first-barrier-test.md` — barrier semantics and the 401/403/404 result-interpretation table.

## Global Constraints

- **Stack workflow per task:** on the task's branch → commit `-s` → `gh stack rebase --upstack` → `gh stack push`. Never edit a lower branch's concern on a higher branch.
- **Order is mandatory:** tasks execute strictly bottom→top (Task 1 → Task 13) so each upstack rebase sees at most one new change-set.
- **TDD discipline:** every behavior change lands its failing test in the same commit-run sequence (red → green). Deny-path regression tests (unauthenticated / wrong team / feature-off) accompany every security-sensitive change (AGENTS.md).
- **detect-secrets gotcha (hit this session):** if the pre-commit hook fails with "secrets in baseline file which have not been audited yet", compare `.secrets.baseline` entries against the pre-edit branch head and restore dropped *audited* entries; never bulk-regenerate on a stack branch.
- **Uncommitted worktree drift:** `tests/conftest.py`-adjacent `.secrets.baseline` often carries 1-line `generated_at` drift after upstack rebases — `git checkout -- .secrets.baseline` **before** `gh stack checkout <branch>` (a dirty baseline silently fails the switch and commits land on the wrong branch; this also happened this session).
- **Alembic single-head invariant:** after any task that adds a migration, `cd mcpgateway && ../.venv/bin/alembic heads` must print exactly one head. The pre-commit hook checks this too.
- **No new secrets in code/tests;** token material is never printed or committed. `entra-token-*.txt` stay untracked.
- **Line numbers in this plan are post-2026-09-12-rebase approximations.** Locate by symbol name first; the plan names symbols everywhere it matters.
- Live-gateway tests self-skip without a gateway (`MCP_CLI_BASE_URL`, default `http://127.0.0.1:8080`) and honor `TESTS_DNS_PASSTHROUGH_HOSTS` (PR #6797) when real IdP egress is needed.

## Current State (already done — do not redo)

| Item | Where |
|---|---|
| Conftest DNS passthrough + docs | Standalone PR **#6797** (`fix/entra-test-dns-passthrough`), merged-base of the stack |
| Stack re-rooted onto #6797; GitHub stack **#6798**; PR #6726 base retargeted | all 25 branches pushed |
| **F6** migration multi-head fixed (`bf2998718ea1` re-parented onto `5e211ec89cad`) | commit `fa16567b8` on PR **#6734** |
| Barrier test (pinned `401`) live-verified | `tests/live_gateway/test_trust_mode_entra_barrier.py` on PR **#6746** (tip `72b540ca6`) |
| Baseline audit entries restored | commit `b56e1f603` on PR **#6726** |
| F5 (gates) partially pending | Task 12 |

Findings→tasks map: F8→T1(#6728) · F7→T2(#6735) · F9+NB2→T3(#6740) · NB3+NB4→T4(#6741) · NB6→T5(#6742) · NB1→T6(#6744) · F2(ctx)→T7(#6746) · F2(decorator)→T8(#6749) · F1+F4→T9(#6750) · F3→T10(#6751) · F4→T11(#6753) · F5→T12(#6755) · NB5→T13(#6757). NB7 (overage) already ships via #6745/#6757 — documented only. NB8 (`/mcp` transport) is explicitly **out of scope** (separate routing path; the review doc does not block `/a2a` on it).

---

### Task 1 — PR #6728 `refactor/5887-principal-user-id`: carry `user_id` in the RBAC user context (F8)

The function `get_current_user_with_permissions(request, credentials, jwt_token)` in `mcpgateway/middleware/rbac.py` builds the context dict every REST/RPC handler receives. Its authenticated-path returns carry `email`, `is_admin`, teams, and token metadata — **not** `user_id` — so `get_user_id(user_context)` always falls back to the e-mail attribute and #5884's canonical ID never reaches live RBAC checks.

**Files:**
- Modify: `mcpgateway/middleware/rbac.py` (`get_current_user_with_permissions` — every authenticated-path `return {…}`)
- Test: `tests/unit/mcpgateway/middleware/test_rbac_user_context.py` (create if absent; sibling tests live under `tests/unit/mcpgateway/middleware/`)

**Interfaces:**
- Consumes: `get_user_id(user)` from `mcpgateway/auth_context.py` (PR #6726) — resolves `user_id` → `email` → `sub` → `"unknown"`.
- Produces: context dicts gain `"user_id": <canonical>` on every authenticated return path. Downstream consumers use `.get("user_id")` — additive key, no caller breaks.

- [ ] **Step 1: failing test**

```python
# tests/unit/mcpgateway/middleware/test_rbac_user_context.py
import pytest
from mcpgateway.middleware import rbac

@pytest.mark.asyncio
async def test_user_context_carries_canonical_user_id(monkeypatch):
    """The authenticated context must expose the canonical user_id, not only email."""
    # Minimal principal whose user_id diverges from email — the F8 case.
    principal = {"email": "alice@example.com", "user_id": "entra-sub-123", "is_admin": False, "teams": []}
    async def fake_validate(request, credentials):
        return principal
    monkeypatch.setattr(rbac, "validate_token_user", fake_validate, raising=False)
    ctx = await rbac.get_current_user_with_permissions.__wrapped__(request=None, credentials=None, jwt_token=None) if hasattr(rbac.get_current_user_with_permissions, "__wrapped__") else None
    # NOTE: if the function is decorated, call the underlying coroutine the way
    # sibling tests do; adapt to the existing test harness in this directory.
    assert ctx.get("user_id") == "entra-sub-123"
```

(Adapt the invocation pattern to the existing harness in that directory — the assertion line is the contract: `ctx["user_id"] == "entra-sub-123"`.)

- [ ] **Step 2:** run `uv run pytest tests/unit/mcpgateway/middleware/test_rbac_user_context.py -v` → **FAIL** (`KeyError: 'user_id'` / returns `None`).
- [ ] **Step 3:** in every authenticated `return {…}` of `get_current_user_with_permissions`, add `"user_id": get_user_id(user)` (import from `mcpgateway.auth_context`). The proxy path already sets `user_id=proxy_user` — leave it.
- [ ] **Step 4:** rerun → **PASS**. Also `uv run pytest tests/unit/mcpgateway -k "user_context or auth_context" -q`.
- [ ] **Step 5:** commit `-s` (`refactor(rbac): carry canonical user_id in the authenticated user context`), `gh stack rebase --upstack`, `gh stack push`.

---

### Task 2 — PR #6735 `feat/5893-populate-user-id-writers`: FK-safe canonical writers (F7)

`resolve_canonical_user_id(email, db)` (this branch, `mcpgateway/auth_context.py`) returns the opaque `EmailUser.user_id` when it diverges from the e-mail, and the five writer sites store that value into `UserRole.user_email` / `EmailTeamMember.user_email` — columns whose FKs reference `email_users.email`. Diverged rows violate the FK on any enforced backend (the stack's tests run SQLite without enforcement, which is why it passes today). Decision D1 ("column names stay unchanged") is revoked by the review; adopt **additive dual-write**: FK columns hold the e-mail (always FK-valid); the canonical ID gets its own nullable indexed columns.

**Files:**
- Modify: `mcpgateway/db.py` — add `user_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)` to `UserRole` and `EmailTeamMember`.
- Create migration: `mcpgateway/alembic/versions/<new>_add_user_id_to_roles_and_team_members.py`, idempotent (inspector-guarded), `down_revision = "bf2998718ea1"`.
- Modify: the five writer sites (`role_service.assign_role_to_user`; `team_management_service._upsert_membership`; `team_management_service.approve_join_request`; `personal_team_service.create_personal_team`; `team_invitation_service.accept_invitation`).
- Modify: `tests/unit/mcpgateway/test_writer_resolver_audit.py` — audit now asserts dual-write (`resolve_canonical_user_id` **and** `user_email=<email form>`).
- Test: `tests/unit/mcpgateway/services/test_canonical_writer_fk_integrity.py`.

**Interfaces:**
- Produces: `UserRole(user_email=<email>, user_id=<canonical>, …)`, `EmailTeamMember(user_email=<email>, user_id=<canonical>, …)`. Existing-row lookups key on `user_email` (the FK-valid e-mail) — the divergent-row bug class D1's re-keying tried to prevent is instead handled by `user_id` being present for canonical joins.
- **Chain surgery (expected):** #6741's `e5f6a7b8c9d0` currently has `down_revision = "bf2998718ea1"`. After this task's upstack rebase, alembic sees two heads; resolve by editing `e5f6a7b8c9d0.down_revision` to this task's new revision on branch `feat/5976-external-group-mappings`, then `alembic heads` → single head.

- [ ] **Step 1: failing test** — FK-enforced SQLite proving both the violation and the fix contract:

```python
# tests/unit/mcpgateway/services/test_canonical_writer_fk_integrity.py
import sqlite3
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from mcpgateway.db import Base, EmailUser, UserRole, EmailTeamMember, Team
from mcpgateway.services.role_service import RoleService  # adapt import to actual module layout

@pytest.fixture
def fk_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _): dbapi_conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

def _seed_diverged_user(db):
    db.add(EmailUser(email="alice@example.com", user_id="entra-sub-123", password_hash=None, is_active=True))
    db.commit()

def test_role_writer_keeps_fk_valid_and_stores_canonical_id(fk_db, monkeypatch):
    _seed_diverged_user(fk_db)
    svc = RoleService(db=fk_db)  # adapt to real constructor
    svc.assign_role_to_user("alice@example.com", "developer")  # adapt arg order to real signature
    row = fk_db.execute(select(UserRole)).scalar_one()
    assert row.user_email == "alice@example.com"      # FK-valid (F7 contract)
    assert row.user_id == "entra-sub-123"             # canonical preserved (#5884 intent)
```

Mirror the second assertion pair for `EmailTeamMember` via `team_management_service.add_member_to_team`.

- [ ] **Step 2:** run → **FAIL** (current code stores `entra-sub-123` in `user_email`; `user_id` attribute missing on the models).
- [ ] **Step 3:** implement — model columns; idempotent migration; writer sites: keep `user_email=email_argument`, add `user_id=resolve_canonical_user_id(email_argument, db)`; lookups stay e-mail-keyed; update the AST audit test to the dual-write rule; **on the #6741 branch after upstack rebase**, re-parent `e5f6a7b8c9d0` per the callout above.
- [ ] **Step 4:** rerun task test + `uv run pytest tests -k "writer or assign_role or invitation or personal_team or membership" -q` + `alembic heads` (single head).
- [ ] **Step 5:** commit `-s` (`fix(db): keep FK-valid email in user_email columns, store canonical user_id alongside`), rebase upstack (resolve the two-head conflict on #6741 as part of this task), push both branches.

---

### Task 3 — PR #6740 `feat/5898-jwt-trust-config`: compose wiring + claim-collision guard (F9, NB2)

**Files:**
- Modify: `docker-compose.yml` and `docker-compose.sso.yml` — gateway service `environment:` lists.
- Modify: `mcpgateway/config.py` — `Settings.validate_security_combinations` (the validator that raises `SecurityConfigurationError`).
- Test: `tests/unit/mcpgateway/test_jwt_trust_config.py` (exists on this branch).

- [ ] **Step 1: failing tests**

```python
def test_claim_teams_cannot_alias_group_mapping_source():
    with pytest.raises(Exception) as ei:
        _settings(JWT_CLAIM_TEAMS="groups", JWT_TRUST_GROUPS_CLAIM="groups")  # adapt to real env/field names
    assert "JWT_CLAIM_TEAMS" in str(ei.value)

def test_compose_declares_trust_flags():
    text = Path("docker-compose.yml").read_text()
    assert "JWT_TRUST_MODE" in text and "SSO_API_TOKEN_AUTH_ENABLED" in text
```

(The exact groups-claim field name is `settings.jwt_trust_groups_claim`-family — read `config.py` on this branch for the literal name before writing the test.)

- [ ] **Step 2:** run → **FAIL**.
- [ ] **Step 3:** implement — compose: add both flags as **commented, default-off** entries (`# JWT_TRUST_MODE=db`, `# SSO_API_TOKEN_AUTH_ENABLED=false`) in the explicit env block with a pointer to `docs/docs/manage/*trust*`; config: reject `jwt_claim_teams` configured to the same claim the group-mapping resolver consumes (raise `SecurityConfigurationError` with remediation text naming both variables).
- [ ] **Step 4:** rerun → **PASS**; `uv tool run yamllint docker-compose.yml docker-compose.sso.yml`.
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 4 — PR #6741 `feat/5976-external-group-mappings`: uniqueness + cache invalidation (NB3, NB4)

`ExternalGroupMapping.__table_args__` has `UniqueConstraint("issuer", "tenant", "external_group_id")` — nullable `tenant` lets duplicate (issuer, group) rows coexist on SQLite and PostgreSQL. Separately, `_external_identity_cache` (`mcpgateway/utils/verify_credentials.py:488`, `token_hash -> (payload, expires_at)`) ignores mapping mutations; `invalidate_external_identity_cache()` exists (line 518) but nothing calls it on mapping CRUD.

**Files:**
- Modify: `mcpgateway/db.py` (mapping model), new idempotent migration for the partial index.
- Modify: `mcpgateway/services/external_group_mapping_service.py` (create/update/delete) — call `invalidate_external_identity_cache()` after every successful mutation.
- Test: `tests/unit/mcpgateway/services/test_external_group_mapping_service.py` (exists on this branch — extend).

- [ ] **Step 1: failing tests**

```python
def test_duplicate_null_tenant_mapping_rejected(db_session):
    svc = ExternalGroupMappingService(db_session)  # adapt to real constructor
    svc.create_mapping(issuer="https://sts.example", tenant=None, external_group_id="g-1", team_id="t1", cf_role="developer")
    with pytest.raises(DuplicateMappingError):     # adapt to the service's real error type
        svc.create_mapping(issuer="https://sts.example", tenant=None, external_group_id="g-1", team_id="t2", cf_role="viewer")

async def test_mapping_delete_invalidates_external_identity_cache(...):
    # resolve teams for a token -> ["t1"]; delete the mapping via the service;
    # resolve the SAME token again -> teams no longer contain "t1" (cache was cleared).
```

- [ ] **Step 2:** run → **FAIL** (second insert succeeds today; stale team survives deletion).
- [ ] **Step 3:** implement — migration adds partial unique index `WHERE tenant IS NOT NULL` plus an application-level pre-check for the NULL-tenant case (emit the service's existing conflict error); import and call `invalidate_external_identity_cache()` in create/update/delete success paths.
- [ ] **Step 4:** rerun → **PASS**; `alembic heads` single head.
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 5 — PR #6742 `feat/6272-group-role-mapping`: scope-exact role resolution (NB6)

`cf_role` resolution looks roles up by name while `roles.name` uniqueness is `(name, scope)`-scoped — duplicate names across scopes can union more permissions than intended.

**Files:**
- Modify: the role-resolution helper this branch adds for `cf_role` → team-role mapping (`mcpgateway/services/external_group_mapping_service.py` or the resolver module this branch owns — locate by the query against `Role.name`).
- Test: extend this branch's role-mapping test module.

- [ ] **Step 1: failing test**

```python
def test_cf_role_resolves_scope_exact(db_session):
    # two active roles named "developer": scope="global" (viewer-equivalent perms) and scope="team:alpha"
    # mapping cf_role="developer" scoped to team alpha must resolve ONLY the team:alpha row
    resolved = resolver.resolve_role("developer", team_id="alpha")  # adapt names
    assert resolved.scope == "team:alpha"
```

- [ ] **Step 2:** run → **FAIL** (both rows returned / arbitrary first row).
- [ ] **Step 3:** implement — resolve by `(name, scope)` with the mapping's team scope, falling back to the global scope only when no team-scoped row exists, never unioning.
- [ ] **Step 4:** rerun → **PASS** plus the branch's existing mapping tests.
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 6 — PR #6744 `feat/5899-trusted-claims-module`: strict admin-claim typing (NB1)

`mcpgateway/utils/trusted_claims.py` (~line 372): `is_admin = bool(_get_claim(payload, settings.jwt_claim_admin))` — string `"false"`, `"0"`, `"no"` all coerce truthy. Fail-closed posture demanded by AGENTS.md ("missing admin claim means non-admin").

**Files:**
- Modify: `mcpgateway/utils/trusted_claims.py` — replace the coercion with a strict parser.
- Test: `tests/unit/mcpgateway/utils/test_trusted_claims.py` (exists on this branch — extend).

- [ ] **Step 1: failing test**

```python
@pytest.mark.parametrize("claim,expected", [
    (True, True), ("true", True), ("True", True), ("1", True), (1, True),
    (False, False), ("false", False), ("0", False), (0, False), ("no", False),
    ("", False), (None, False), ([], False), ({"x": 1}, False),  # malformed types are non-admin
])
def test_admin_claim_strict_typing(claim, expected):
    assert extract_admin_flag({"adminclaim": claim}) is expected  # adapt to real symbol/settings
```

- [ ] **Step 2:** run → **FAIL** for `("false", False)`, `("no", False)`, `("0", False)` at minimum.
- [ ] **Step 3:** implement — truthy set `{"true","1","yes",1,True}` case-insensitive; every other JSON type/value → `False`; log a warning (structured) when a non-boolean, non-canonical-string claim was present and coerced false.
- [ ] **Step 4:** rerun → **PASS** (all 14 rows).
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 7 — PR #6746 `feat/5900-trust-branch`: carry claims-derived identity into the user context (F2, first half)

`VirtualPrincipal` carries `user_id`, `roles`, `is_admin`, `token_teams`; `get_current_user_with_permissions` drops `roles` (and `is_admin` stays DB-derived). Carry them through so Task 8 can forward them.

**Files:**
- Modify: `mcpgateway/middleware/rbac.py` — the trust-branch principal construction inside `get_current_user_with_permissions` (this branch's `VirtualPrincipal` integration).
- Test: `tests/unit/mcpgateway/middleware/test_rbac_user_context.py` (from Task 1 — extend).

- [ ] **Step 1: failing test**

```python
@pytest.mark.asyncio
async def test_trust_principal_roles_reach_user_context(monkeypatch):
    # principal from the trust branch with claims-derived roles and admin flag
    principal = {"user_id": "entra-sub-123", "email": "alice@example.com",
                 "roles": ["developer"], "token_is_admin": False, "token_teams": ["team-a"]}
    ctx = await _invoke_user_context(rbac, principal, monkeypatch)  # harness from Task 1
    assert ctx.get("roles") == ["developer"]
    assert ctx.get("token_is_admin") is False
    assert ctx.get("token_teams") == ["team-a"]
    assert ctx.get("user_id") == "entra-sub-123"
```

- [ ] **Step 2:** run → **FAIL** (`roles` missing).
- [ ] **Step 3:** implement — trust-path context dict gains `roles` (default `[]`) and `token_is_admin` (default `False`) sourced from the principal; non-trust paths get the same keys with neutral defaults so downstream consumers can rely on key presence.
- [ ] **Step 4:** rerun → **PASS**; full `tests/unit/mcpgateway/middleware -q`.
- [ ] **Step 5:** commit `-s`, rebase upstack, push. *(Barrier test stays pinned at 401 — ingress is Task 9.)*

---

### Task 8 — PR #6749 `feat/5902-admin-claim-parity`: forward `token_roles`/`token_is_admin` into `PermissionService` (F2, second half)

`PermissionService.check_permission` already accepts `token_is_admin`/`token_roles` (added on this branch), but the decorator path (`require_permission` → `check_permission_inline`, `mcpgateway/middleware/rbac.py`) never passes them, so trust-only principals fall back to empty local `EmailUser`/`UserRole` queries.

**Files:**
- Modify: `mcpgateway/middleware/rbac.py` — `check_permission_inline` and the decorator call sites (locate every `check_permission(` in the file).
- Test: `tests/unit/mcpgateway/middleware/test_rbac_decorator_forwards_token_roles.py`.

- [ ] **Step 1: failing test**

```python
@pytest.mark.asyncio
async def test_decorator_forwards_token_roles_to_permission_service(monkeypatch, db_session):
    captured = {}
    class RecordingPermissionService(PermissionService):
        async def check_permission(self, db, user_email, permission, **kwargs):
            captured.update(kwargs); return True
    monkeypatch.setattr(rbac, "PermissionService", RecordingPermissionService)
    ctx = {"email": "alice@example.com", "user_id": "entra-sub-123", "is_admin": False,
           "roles": ["developer"], "token_is_admin": False, "token_teams": ["team-a"]}
    ok = await rbac.check_permission_inline(db_session, ctx, "a2a.invoke")  # adapt to real signature
    assert ok is True
    assert captured.get("token_roles") == ["developer"]
    assert captured.get("token_is_admin") is False
```

- [ ] **Step 2:** run → **FAIL** (`captured` empty).
- [ ] **Step 3:** implement — every decorator-path `check_permission(...)` call forwards `token_roles=ctx.get("roles", [])` and `token_is_admin=ctx.get("token_is_admin", False)`; verify `PermissionService` honors `token_roles` for `a2a.invoke` when no local `UserRole` rows exist (this branch's unit tests for the service params should already assert it — extend if not).
- [ ] **Step 4:** rerun → **PASS**; `tests/unit/mcpgateway -k "permission or admin_claim" -q`.
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 9 — PR #6750 `feat/5903-external-idp-trust-root`: the ingress fix + black-box matrix (F1, F4) — the pivot task

`get_current_user()` (`mcpgateway/auth.py`, the `payload = await verify_jwt_token_cached(credentials.credentials, request)` site) accepts gateway-signed JWTs only. External dispatch exists in `verify_credentials_cached()` → `_maybe_verify_external()` → `verify_external_idp_token()` → `build_trusted_external_identity()` (`mcpgateway/utils/verify_credentials.py:649,716,2236`) but is never reached from this route.

**Files:**
- Modify: `mcpgateway/auth.py` — `get_current_user()` bearer dispatch.
- Create: `tests/live_gateway/helpers/local_oidc_issuer.py` — minimal FastAPI app serving `/.well-known/openid-configuration` + JWKS from a test RSA key; fixture starts it on an ephemeral port.
- Create: `tests/live_gateway/test_trust_mode_external_ingress_e2e.py` — the black-box matrix.
- Modify: `tests/live_gateway/test_trust_mode_entra_barrier.py` — **flip** the pinned expectation (file born on #6746; editing it upstack is correct).

**Interfaces:**
- Consumes: `verify_credentials_cached(token, request)` (returns payload or raises `TokenValidationError`); trust-root config via `SSOProvider(trusted_for_api_auth=…, api_audience=…)`; `JWT_TRUST_REVOCATION_CLAIM` (default `jti`) enforcement already in the external path.
- Produces: external bearers authenticate via the external verifier **before** the internal one; unknown issuer / bad signature / wrong audience / missing revocation claim → `401` fail-closed; gateway-signed JWTs behave exactly as before.

- [ ] **Step 1: black-box matrix, failing** (gateway subprocess in trust mode; local OIDC issuer as the "Entra-compatible" trust root; provider row + team + agent + mapping seeded via admin API):

```python
# tests/live_gateway/test_trust_mode_external_ingress_e2e.py
MATRIX = [
    # (scenario, expected)
    ("mapped_user_invokes_agent", 200),          # #6272 acceptance row
    ("unmapped_user_invoke", 403),               # deny without disclosing (authn ok, RBAC deny)
    ("wrong_audience_token", 401),
    ("missing_revocation_claim", 401),           # no jti/uti -> reject
    ("nonexistent_agent_with_role", 404),        # the barrier doc's success condition
]
@pytest.mark.parametrize("scenario,expected", MATRIX)
def test_ingress_matrix(scenario, expected, gateway_trust_mode, local_oidc_issuer): ...
```

Seed: team `agent-a-team`; agent `Agent-A` with `visibility="team"`; mapping `local-issuer-group-1 → team + developer`; tokens RS256-signed by the local issuer's key (mapped user carries group claim, unmapped user doesn't; audience variant; no-jti variant). Run: `MCP_CLI_BASE_URL=… JWT_TRUST_MODE=jwt-trust uv run pytest … -v --with-integration` → **FAIL** (`401 != 200/403/404`).

- [ ] **Step 2: implement the dispatch.** In `get_current_user()`, before the internal verifier: try the external path when trust mode is on —

```python
if settings.jwt_trust_mode == "jwt-trust":
    external_payload = await _try_external_verification(credentials.credentials, request)
    if external_payload is not None:
        payload = external_payload          # trusted external principal
    else:
        payload = await verify_jwt_token_cached(credentials.credentials, request)  # internal funnel
```

where `_try_external_verification` wraps `verify_credentials_cached`'s external branch and returns `None` **only** for "not an external-issuer token" (issuer not a configured trust root); every definitive verification failure (bad signature, wrong aud, expired, missing revocation claim) must raise → `401`, never fall through to the internal funnel (fail-closed; matches the dispatch rule doc'd in #6738 and AGENTS.md's trust-mode dispatch rule). Self-test: internal JWT still works; `token_use="trusted"` gateway-signed marker with trust mode ON still routes per the #5896 matrix.
- [ ] **Step 3: matrix green; barrier flip.** `test_valid_entra_user_token_is_blocked_before_external_verification`: barrier scenario has **no** mapping → post-fix result is `403` (authenticated, `a2a.invoke` denied). Flip assertion + rename to `test_valid_entra_user_token_authenticated_without_mapping`; fake-token control stays `401`. Update the module docstring's "Expected result" section.
- [ ] **Step 4:** deny-path regression tests: unauthenticated `/a2a/*/invoke` → 401; trust mode OFF (`JWT_TRUST_MODE=db`) + external token → 401 (never enters default funnel).
- [ ] **Step 5:** full runs: matrix + barrier + `tests/unit/mcpgateway -k "trust or dispatch or verify_credentials" -q`.
- [ ] **Step 6:** commit `-s` (`fix(auth): dispatch external-issuer bearers to the JWKS verifier at the authentication choke point`), rebase upstack, push.

---

### Task 10 — PR #6751 `feat/5904-trust-token-minting`: trust-aware `TokenScopingMiddleware` (F3)

`mcpgateway/middleware/token_scoping.py` special-cases only `token_use == "session"` (lines ~1322–1382); `token_use="trusted"` falls into the API/legacy branch and validates mapped teams against local `email_team_members` — trust-only principals have none → `403 Token is invalid: User is no longer a member of the associated team`.

**Files:**
- Modify: `mcpgateway/middleware/token_scoping.py` — the two `_check_team_membership` guard sites.
- Test: `tests/unit/mcpgateway/middleware/test_token_scoping_trusted.py`.

- [ ] **Step 1: failing test**

```python
async def test_trusted_token_teams_skip_local_membership_check(db_session):
    payload = {"token_use": "trusted", "sub": "entra-sub-123", "teams": ["agent-a-team"], "exp": ...}
    decision = run_scoping_middleware(payload, db_session)   # adapt to the middleware's test harness
    assert decision.allowed is True                          # teams came from the verified resolver

async def test_trusted_token_with_revoked_team_still_denied(db_session):
    # revocation blocklist contains the token's jti -> deny regardless of team handling
    ...
```

- [ ] **Step 2:** run → **FAIL** (first case trips `_check_team_membership`).
- [ ] **Step 3:** implement — when `token_use == "trusted"` and trust mode is on, skip the `email_team_members` membership check for resolver-derived teams (comment citing the AGENTS.md invariant: mapped teams are verified at verification time; revocation stays keyed by the configured claim). Session and legacy branches untouched.
- [ ] **Step 4:** rerun → **PASS**; legacy/session scoping tests unchanged.
- [ ] **Step 5:** commit `-s`, rebase upstack, push.

---

### Task 11 — PR #6753 `feat/5905-trust-mode-acceptance-suite`: route-level dispatch matrix (F4, completion)

The dispatch matrix (`tests/unit/mcpgateway/test_token_dispatch_matrix.py`) calls `_maybe_verify_external()` directly; the group-role flow (`test_trust_role_merge.py`) patches `verify_jwt_token_cached` and drives functions directly. Re-route both through the real entry points now that Task 9 makes that possible.

**Files:**
- Modify: `tests/unit/mcpgateway/test_token_dispatch_matrix.py` — drive `get_current_user()` (mock only the JWKS fetch, not the dispatch) and assert the same matrix incl. the cross-mode deny rows.
- Modify: `tests/unit/mcpgateway/test_trust_role_merge.py` — replace the `verify_jwt_token_cached` patch with externally-signed fixtures via Task 9's `local_oidc_issuer` helper (import from `tests/live_gateway/helpers/`); exercise `get_current_user_with_permissions` + `check_permission_inline` instead of manual role derivation.
- Test evidence: live `make test-mcp-rbac`-style run with `JWT_TRUST_MODE=jwt-trust` gate (self-skips without gateway, mirroring `test_trust_mode_rbac.py`).

- [ ] **Steps:** (1) convert matrix rows one class at a time, red-first where the old assertion encoded the patched shortcut (e.g. asserting `_maybe_verify_external` was called); (2) run `-k "dispatch_matrix or trust_role" -v`; (3) commit `-s`, rebase upstack, push.

---

### Task 12 — PR #6755 `docs/5906-trust-mode-docs-gate`: validation gates + docs truth (F5, F9-docs)

- [ ] **Step 1:** update docs to the post-fix reality: ingress dispatch behavior (`docs/docs/manage/…trust…` pages on this branch), compose wiring from Task 3 ( uncommented pointer + full provider setup incl. `TESTS_DNS_PASSTHROUGH_HOSTS` for the Entra E2E suite), and the barrier semantics table (401 fixed / 403 unmapped / 404 nonexistent).
- [ ] **Step 2:** run the AGENTS.md pre-merge gate in order, from the worktree root: `make ruff interrogate pylint` → `make test` → `make coverage diff-cover` → `make docker-nuke docker-prod-rust testing-up RUST_MCP_MODE=` → `make test-mcp-protocol-e2e test-mcp-rbac` (plus a trust-mode pass: restart stack with `JWT_TRUST_MODE=jwt-trust SSO_API_TOKEN_AUTH_ENABLED=true` and rerun `test-mcp-rbac` + `tests/live_gateway/test_trust_mode_*`) → `make detect-secrets-scan`. Record each result in the PR description (the gate evidence convention this branch already follows).
- [ ] **Step 3:** commit `-s`, rebase upstack, push.

---

### Task 13 — PR #6757 `feat/6756-app-only-graph-lookup`: wire the real group-existence validator (NB5)

`mcpgateway/routers/admin_external_group_mappings.py` ships `group_exists_validator = _disabled_group_exists_validator` (always `"valid"`); this branch introduces the app-only Graph client that can make it real.

**Files:**
- Modify: `mcpgateway/routers/admin_external_group_mappings.py` — replace the stub default with a Graph-backed validator (issuer-scoped: only for Entra trust roots; non-Microsoft issuers keep `"valid"` with a log line).
- Test: `tests/unit/mcpgateway/routers/test_admin_external_group_mappings.py` (exists on this branch — extend with a mocked Graph client: exists → `"valid"`, 404 → rejected, Graph error → fail-closed `"unverified"` + warning).

- [ ] **Steps:** failing test with the mocked client seam → wire validator (reusing this branch's Graph client; disabled via existing settings flag when credentials absent) → green → commit `-s` → rebase upstack (top of stack: no further branches) → push.

---

## Self-Review

**Spec coverage:** F1→T9 · F2→T7+T8 · F3→T10 · F4→T9+T11 · F5→T12 · F6→done (baseline) · F7→T2 · F8→T1 · F9→T3+T12 · NB1→T6 · NB2→T3 · NB3→T4 · NB4→T4 · NB5→T13 · NB6→T5 · NB7→documented (#6745/#6757, no code) · NB8→out of scope (stated). "What Is Still Needed": 1→T12(rebases are continuous)+baseline · 2→T9 · 3→T7 · 4→T8 · 5→T10 · 6→T2 · 7→T6 · 8→T3 · 9→T9 · 10→T12. No gaps.

**Type consistency:** `user_id`/`roles`/`token_is_admin` context keys identical in T1/T7/T8; `resolve_canonical_user_id(email, db)` (existing) used by T2; `invalidate_external_identity_cache()` (existing, verify_credentials:518) used by T4; `verify_credentials_cached(token, request)` consumed by T9; `local_oidc_issuer` helper created in T9, reused by T11.

**Known execution risks:** T2's migration re-parent of `e5f6a7b8c9d0` (called out in-task); T9 is the largest diff — if the matrix's unmapped-user row yields `404` instead of `403` (visibility checked before RBAC on this route), record the observed code and pin *that* — the security contract is "deny without disclosing agent existence", not the specific code.
