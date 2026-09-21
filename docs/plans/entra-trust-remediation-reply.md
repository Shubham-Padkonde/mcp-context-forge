# Reply: Entra Trust-Mode Remediation — Changes, Process, and Testing

**This document gives an answer to:**
- `entra-a2a-first-barrier-test.md` (the A2A first-barrier test)
- `epic-investigation.md` (the #5884/#5885 stack investigation)

**Date:** 2026-09-13
**Stack:** GitHub stack #6798. The stack has 25 open pull requests (PR). The stack root is `fix/entra-test-dns-passthrough` (PR #6797). The stack tip is `feat/6756-app-only-graph-lookup` (PR #6757, head `aae0b9707`).
**Plan:** `entra-trust-remediation-plan.md`. The plan has 13 tasks (T1–T13). The team did the tasks in stack order, from bottom to top.

---

## 1. Disposition of each finding

First, the tests showed each blocking failure. Then the team corrected it. NB means a concern that does not block.

| # | Finding (epic-investigation) | Disposition | PR |
|---|---|---|---|
| F1 | Entra tokens never reach the trust-mode branch. `get_current_user` uses the internal verifier only. | Verified live, then corrected. `get_current_user` now sends external-issuer bearers to the JWKS path (`_try_external_verification`). A valid token from a trust root gives an external principal. A bad token from a trust root gives 401. The code does not fall through to the internal funnel. A token with another issuer uses the internal funnel, as before. The unverified peek reads the `iss` claim only. | #6750 |
| F2 | Claims-derived roles do not reach the RBAC decorator. | Corrected in two layers. Context dictionaries now carry `user_id` (F8), `roles`, `token_is_admin`, and `token_teams`. All 8 decorator-path `check_permission` calls forward `token_roles` and `token_is_admin`. Claims-role resolution is scope-exact. `check_admin_permission` also obeys the claims admin flag. A trust principal with `roles=["developer"]` and no local rows now gets `a2a.invoke`. | #6746, #6749 |
| F3 | `TokenScopingMiddleware` needs local team membership. | Verified live. The middleware blocked 2 of 5 matrix rows. Then corrected. A `token_use="trusted"` token in `jwt-trust` mode does not get the `email_team_members` check for resolver-derived teams. Revocation and expiry checks stay active. Session and legacy branches did not change. | #6751 |
| F4 | Acceptance tests do not use the real request path. | Corrected. The dispatch matrix and the group-role flow now drive `get_current_user`, then `get_current_user_with_permissions`, then `check_permission_inline`. The tests mock the JWKS fetch only. An independent test proved the value: when the F1 dispatch was removed, 9 of 16 converted tests failed. The old patched tests caught none. | #6750, #6753 |
| F5 | The mandatory live validation gate did not run. | Ran and passed. See section 4 for all six gates. | #6755 |
| F6 | The migration stack makes two Alembic heads. | Verified live at the first gateway start (`MultipleHeads: 5e211ec89cad, f7a8b9c0d1e2`). Then corrected by re-parenting. The chain is now linear and has one head: `5e211ec89cad → bf2998718ea1 → a824749abd27 → e5f6a7b8c9d0 → b7c8d9e0f1a2 → f7a8b9c0d1e2`. | #6734, #6741, #6747 |
| F7 | Canonical-ID writers break the `email_users.email` foreign keys. | Corrected with additive dual-write. The `user_email` columns keep the e-mail, so the foreign keys stay valid. New nullable indexed `user_id` columns hold the canonical id. Lookups stay keyed on e-mail. An AST audit test enforces dual-write at every construction site. A SQLite test with `PRAGMA foreign_keys=ON` proves the contract. Canonical-id readers now match both keys (`or_(user_email, user_id)`). | #6735 |
| F8 | The RBAC context drops the canonical identity. | Corrected. Every authenticated context return now carries `user_id`. Review caught an accidental deletion of `token_use`; that key was restored with regression tests. | #6728 |
| F9 | The Compose files do not declare the feature flags. | Corrected. `JWT_TRUST_MODE` and `SSO_API_TOKEN_AUTH_ENABLED` now appear as comments in `docker-compose.yml` and `docker-compose.sso.yml`. Both default to off. The entries point to the docs. | #6740 |
| NB1 | `is_admin = bool(claim)` treats `"false"` as admin. | Corrected. The strict parser accepts only `True`, `1`, `"true"`, `"1"`, and `"yes"` (case-insensitive). Known denial strings coerce to false without a log entry. Wrong types give one warning. The warning names the claim and its JSON type, never the value. A 14-row typing matrix covers the parser. | #6744 |
| NB2 | `JWT_CLAIM_TEAMS=groups` can collide with the groups claim. | Corrected. Configuration validation now rejects the collision. The guard covers all three provider claims: `SSO_ENTRA_GROUPS_CLAIM`, `SSO_KEYCLOAK_GROUPS_CLAIM`, and `SSO_GENERIC_GROUPS_CLAIM`. | #6740, widened on #6750 |
| NB3 | The unique constraint lets duplicate rows with `tenant IS NULL`. | Corrected. A new partial unique index covers `WHERE tenant IS NULL`. The service also checks for duplicates on create and update. The reviewer ran the migration against a scratch SQLite database to validate it. | #6741 |
| NB4 | The identity cache key has the token hash only. | Corrected for mapping changes. Create, update, and delete now call `invalidate_external_identity_cache()`. Redis entries stay bounded by their TTL (60 s or less). This is a documented trade-off. | #6741 |
| NB5 | The Graph validator is a disabled stub. | Wired. The real validator checks group existence through Graph. It runs for Microsoft issuers only. A 200 answer gives `valid`. A 404 answer gives the status `graph_group_not_found`. An error gives the pre-existing `unknown` status with a warning. Other issuers get no IdP call. A provider without credentials keeps the current permissive result and logs a warning. | #6757 |
| NB6 | Role lookup uses the name, but role uniqueness is scoped. | Corrected at every point where names become permissions. `resolve_mapping_role` is the single resolution point. It returns one active row. Team scope wins over global scope. The lowest id breaks ties. Rows never merge. The mapping composition, the claims merge, the decorator path, and the admin CRUD validation all use it. | #6742, #6744, #6749 |
| NB7 | The overage policy defaults to `fail_closed`. | Not changed. This is the intended design. The `graph_lookup` policy and the app-only client already exist. No action was needed. | — |
| NB8 | The same token does not work on the `/mcp` transport. | Out of scope for this remediation. That path uses separate routing. The review does not block `/a2a` on it. A future task set can address it. | — |

### Answer to the barrier test

The barrier document asked one question. Why does a valid Entra token get `401` before external verification, group mapping, RBAC, or agent lookup? The tests answered it at runtime. A temporary `AUTH_DIAGNOSTIC` marker showed entry into `verify_jwt_token_cached`. The rejection came 152 µs later with the same request id. No success log followed. The team then removed the marker.

The results after the fix, verified live:

| Request | Result | Cause |
|---|---|---|
| Valid Entra token, no trust root seeded (barrier scenario) | `401` | Correct fall-through. An untrusted issuer goes to the internal verifier. The barrier file now pins this contract: `test_valid_entra_user_token_untrusted_issuer_falls_to_internal_verifier`. |
| Valid token from a seeded trust root, user not mapped | `403` | The user is authenticated. `a2a.invoke` is denied. The response does not disclose agents. Live matrix row. |
| Mapped and authorized user, real agent | `200` | The acceptance row of issue #6272, proven end to end. |
| Authorized user, agent does not exist | `404` | The success condition wanted by the barrier document. The matrix proves it. |

---

## 2. Changes made

The stack holds 57 commits (base `fix/entra-test-dns-passthrough` to tip `aae0b9707`).

**Identity foundation (Epic #5884 lineage):**
- #6728: `user_id` now travels in every authenticated RBAC context. The `token_use` key stays, with regression tests.
- #6735: Writers use FK-safe dual-write. `user_email` holds the e-mail. New `user_id` columns hold the canonical id. Migration `a824749abd27` adds the columns. An AST audit enforces dual-write. Readers match both keys (`163cc16f8`).

**Trust machinery (Epic #5885 lineage):**
- #6740: Compose flag declarations. Claim-collision guard.
- #6741: Partial unique index for NULL tenants (`b7c8d9e0f1a2`). Cache invalidation on mapping CRUD. Migration re-parent.
- #6742: Scope-exact `resolve_mapping_role`.
- #6744: Strict admin-claim parsing. Scope-exact claims-role merge. The resolver moved to `mcpgateway/services/role_resolution.py`.
- #6746: Context carries `roles`, `token_is_admin`, and `token_teams`. The None-versus-empty-list semantics match the Layer-1 admin-bypass contract.
- #6749: Decorator forwarding at all call sites. Admin-track parity.
- #6750: The ingress fix. `_try_external_verification` in `get_current_user`. Guard widening. Local OIDC issuer harness. Live matrix. Barrier re-pin.
- #6751: Trusted-team scoping exemption.
- #6753: Patched tests converted to the real entry points.
- #6755: Five doc pages updated. Gate remediations.
- #6757: Real Graph validator. Final import-cycle fix (`aae0b9707`).

**Prerequisite outside the stack:** PR #6797 (`fix/entra-test-dns-passthrough`) sits directly on `main`. The conftest DNS stub sent every external hostname to one constant address. This blocked all IdP traffic from tests under `tests/`. The Entra E2E suite could not pass as shipped. The fix adds opt-in `TESTS_DNS_PASSTHROUGH_HOSTS` and IDNA bytes-host normalization. `entra-id-e2e.md` documents the variables. The full 25-PR stack was re-rooted onto this branch.

---

## 3. How the team ran the revision

1. **Replication first.** The tests showed each documented failure before any fix. The barrier curl pair gave `401 {"detail":"Invalid authentication credentials"}` for both tokens. The runtime marker gave the proof at the choke point. The first gateway start gave the migration error. The credentials were derived live: a disposable Entra user through Graph, an ROPC end-user token, and the tenant default domain. No credential was printed. The disposable user was deleted after the test.
2. **Plan.** The 13-task plan mapped each finding to the PR that owns the code. The task order follows the stack from bottom to top. Each `gh stack rebase --upstack` then moved one change-set at a time. Two migration re-parents ran inside the flow, as planned.
3. **Per-task loop.** One implementer built the failing test first (red). The implementer then wrote the fix (green) and made a signed commit. An independent reviewer then checked two things: spec compliance and code quality. The reviewer could re-run tests and probe the change. Findings went back to the implementer as bounded fix rounds. A scoped re-review closed each round. Fix rounds ran on #6746 (accidental `token_use` deletion), #6749 (two findings in that branch's own base code), and #6750 (barrier semantics).
4. **Security-weighted review.** The ingress fix (#6750) and the scoping exemption (#6751) got an adversarial security review. The probes covered forgery through the `iss` peek, swallowed exceptions, guard bypass, exemption over-reach, and mapping-deletion propagation. No bypass path survived.
5. **Whole-branch final review.** A final reviewer triaged every deferred minor item. The reviewer also checked the cross-task seams: dispatch against scoping against decorator; writers against readers against cache keys; the combined test surface; the migration ancestry; and the docs against the code. One P2 defect remained: an import cycle introduced inside the change set. A single final wave corrected it and a stale doc row. Execution verified the fix. Verdict: **SHIP**.
6. **Gate discipline.** All six AGENTS.md gates ran on the docs-gate branch before the final review. Section 4 gives the results.

---

## 4. Tests created and executed

### New and converted test assets

| Asset | Layer | Covers |
|---|---|---|
| `tests/unit/mcpgateway/middleware/test_rbac_user_context.py` | unit | F8, F2a. Key presence and values on every authenticated path. `token_use` regression. |
| `tests/unit/mcpgateway/services/test_canonical_writer_fk_integrity.py` | unit | F7. FK-enforced SQLite dual-write contract for `UserRole` and `EmailTeamMember`. Diverged-user dual-key team resolution. |
| `tests/unit/mcpgateway/test_writer_resolver_audit.py` (updated) | unit | AST audit. Every writer construction site dual-writes. |
| `tests/unit/mcpgateway/test_jwt_trust_config.py` (extended) | unit | F9, NB2. Collision guard across all three provider claims. Compose declarations. |
| `tests/unit/mcpgateway/services/test_external_group_mapping_service.py` plus router tests (extended) | unit | NB3, NB4. Duplicate rejection on create and update. Cache invalidation on CRUD. |
| Role-mapping tests (extended, #6742) | unit | NB6. Scope-exact resolution, tie-break, inactive filtering. |
| `tests/unit/mcpgateway/test_trusted_claims.py` (extended) | unit | NB1. 14-row strict typing matrix and warning contract. NB6. Scope-exact merge. |
| `tests/unit/mcpgateway/middleware/test_rbac_decorator_forwards_token_roles.py` | unit | F2b. Kwarg forwarding. Grant and deny matrix for a trust principal with no local rows. |
| `tests/unit/mcpgateway/middleware/test_token_scoping_trusted.py` | unit | F3. Trusted teams exempt. Revoked jti still denied. Legacy still denied. |
| `tests/unit/mcpgateway/test_token_dispatch_matrix.py` (converted) | unit | F4. External rows drive `get_current_user`. JWKS fetch mocked only. |
| `tests/unit/mcpgateway/test_trust_role_merge.py` (converted) | unit | F4. Full decorator chain. Externally-signed fixtures. |
| `tests/unit/mcpgateway/test_identity_separation.py` (aligned) | unit | F7 contract. Dual-key findability. The canonical id never enters the FK column. |
| Graph-validator tests (extended, #6757) | unit | NB5. The 200/404/error/issuer-scope/no-credentials matrix. No-client-call assertions. |
| `tests/live_gateway/helpers/local_oidc_issuer.py` | harness | Entra-compatible local OIDC issuer. Discovery, JWKS, and RS256 token minting. |
| `tests/live_gateway/test_trust_mode_external_ingress_e2e.py` | live | F1, F4. Five-row black-box matrix. |
| `tests/live_gateway/test_trust_mode_entra_barrier.py` | live | Barrier evidence. Fake-token 401 control. Valid-token untrusted-issuer fall-through 401. |

### Live results (trust-mode gateway, real HTTP)

```
matrix:  mapped_user_invokes_agent        200   (#6272 acceptance row)
         unmapped_user_invoke             403   (deny without disclosure)
         wrong_audience_token             401
         missing_revocation_claim         401
         nonexistent_agent_with_role      404
barrier: fake token                       401
         valid Entra token (unseeded)     401   (correct fall-through)
```

### Gate run (PR #6755 branch)

| Gate | Result |
|---|---|
| `make ruff interrogate pylint` | PASS. Interrogate 100.0% (5522/5522). Pylint 10.00/10. |
| `make test` | PASS. 23,561 passed, 906 skipped, 2 xfailed. |
| `make coverage diff-cover` | PASS. 97% diff coverage. 34 of 1205 changed lines have no coverage. |
| Docker stack, `test-mcp-protocol-e2e`, `test-mcp-rbac` | PASS. 19 and 40 passed. |
| Trust-mode live pass | PASS. 7 of 7. Matrix 5 of 5, barrier 2 of 2. The rows ran; they did not skip. |
| `make detect-secrets-scan` | PASS. 546 entries reviewed. No live or unaudited finding. |

---

## 5. Accepted residual items

The final review accepted these items. None of them loosens security:

- Redis identity-cache entries can stay stale for 60 s or less in a multi-worker deployment.
- A gateway-minted trust token keeps its mapped teams until it expires or an operator blocks its jti.
- The `/admin/*` dashboard track (`has_admin_permission`) does not read the claims admin flag.
- Role resolution makes one query per role name (N+1).
- No test row forces a JWKS outage on the trust-root path.
- The Graph revalidation on mapping update has no direct test.
- The validator holds its database session across the Graph round trips.

Out of scope by record: NB8 (the `/mcp` transport for external tokens) and a compose-stack trust-mode rerun of `test-mcp-rbac`. The standalone gateway ran the same code and environment, so the team accepted it as the gate-5 equivalent.

## 6. Where to find the evidence

- Plan: `entra-trust-remediation-plan.md`. Original reviews: the two documents this replies to.
- Live proof: the module docstring of `tests/live_gateway/test_trust_mode_external_ingress_e2e.py` gives the exact gateway startup environment.
- Merge order: bottom to top, from PR #6797 through stack #6798.
