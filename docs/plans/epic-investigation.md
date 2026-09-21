# NOT READY

Even if the complete implementation stack for issues [#5884](https://github.com/IBM/mcp-context-forge/issues/5884) and [#5885](https://github.com/IBM/mcp-context-forge/issues/5885) were merged now, the requested Entra user-token flow would not work end-to-end.

The most immediate runtime result would be:

```http
POST /a2a/Agent-A/invoke
Authorization: Bearer <valid Entra user access token>

HTTP/1.1 401 Unauthorized
{"detail":"Invalid authentication credentials"}
```

If the authentication ingress were fixed independently, the request would then encounter additional authorization and token-scoping problems, most likely producing `403` before Agent-A is invoked.

**Desired Behavior**

A Microsoft Entra end-user access token should be sufficient to authenticate a user without creating or loading a local ContextForge user record.

For an Agent-A deployment:

1. ContextForge validates the token against the configured Entra issuer, JWKS, and audience.
2. It extracts the stable user identity and Entra group object IDs.
3. `Agent-A-Users` is mapped to Agent-A's ContextForge team and an RBAC role such as `developer`.
4. The team mapping grants Layer-1 visibility to Agent-A.
5. The mapped role grants Layer-2 `a2a.invoke`.
6. An enabled Agent-A registered with `visibility="team"` and the mapped team is invoked.
7. A user without the mapping is denied without learning that the agent exists.

That is also the intent recorded in [#5976](https://github.com/IBM/mcp-context-forge/issues/5976) and [#6272](https://github.com/IBM/mcp-context-forge/issues/6272).

**End-To-End Validation**

I validated:

- Current local `main`, aligned with `origin/main` at `b9027c73999b`.
- The complete proposed stack at PR [#6755](https://github.com/IBM/mcp-context-forge/pull/6755), commit `1994d612518a`.
- The linked implementation PRs and issue acceptance criteria.
- Authentication, external JWKS verification, claims extraction, group mapping, RBAC, token scoping, A2A visibility, migrations, configuration, and tests.

None of the #5884 or #5885 implementation PRs is currently merged. All child issues remain open. More importantly, the problems below exist in the complete stack tip, not merely on current `main`.

The intended flow is partially implemented:

- External issuer and JWKS verification already exists in `mcpgateway/utils/verify_credentials.py`.
- PR #6750 adds claims-derived external identities without local user provisioning.
- PR #6741 adds the `external_group_mappings` table and resolver.
- PR #6742 adds `cf_role` mappings.
- PR #6746 adds a `VirtualPrincipal` trust branch.
- Agent visibility correctly checks `agent.team_id in token_teams` in `mcpgateway/services/a2a_service.py:471-531`.
- Invocation routes require `a2a.invoke` in `mcpgateway/main.py:5359`, `5407`, and `5460`.

Those pieces are not connected correctly through the real HTTP execution path.

**Blocking Issues**

1. **Real Entra tokens never reach the trust-mode branch**

   At the stack tip, `get_current_user()` still calls the internal ContextForge verifier:

   - Proposed stack: `mcpgateway/auth.py:1765-1767`
   - Current `main`: `mcpgateway/auth.py:1694-1696`

   ```python
   payload = await verify_jwt_token_cached(credentials.credentials, request)
   ```

   External issuer dispatch is implemented under `verify_credentials_cached()`:

   - `mcpgateway/utils/verify_credentials.py:650-710`
   - `mcpgateway/utils/verify_credentials.py:716-740`

   But `get_current_user()` never calls it. A genuine Entra-signed token therefore fails ContextForge's internal signature verification before `token_use="trusted"` can be constructed or interpreted.

   Open PR [#6424](https://github.com/IBM/mcp-context-forge/pull/6424) independently identifies and attempts to fix this exact problem. It is not part of the trust stack, remains open and blocked with requested changes, and explicitly does not solve `/mcp`.

   **Runtime consequence:** a valid Entra access token gets `401 Invalid authentication credentials` on the A2A REST invocation endpoint.

2. **Claims-derived roles do not reach the actual RBAC decorator**

   `VirtualPrincipal.roles` correctly receives `developer` from `cf_role`, but `get_current_user_with_permissions()` drops it:

   - `mcpgateway/middleware/rbac.py:537-553` returns `email`, `is_admin`, teams, and token metadata.
   - It does not return `user_id` or `roles`.

   `PermissionService.check_permission()` accepts the new arguments:

   - `token_is_admin`: `mcpgateway/services/permission_service.py:81`
   - `token_roles`: `mcpgateway/services/permission_service.py:82`

   However, the normal RBAC path does not pass either argument:

   - `mcpgateway/middleware/rbac.py:891-918`

   It consequently falls back to local `EmailUser` and `UserRole` queries for a trust-only principal that has no local rows.

   **Runtime consequence:** after fixing Entra token ingress, `Agent-A-Users -> developer` still does not grant `a2a.invoke` through `@require_permission("a2a.invoke")`; the invocation receives `403 Access denied`.

3. **Token-scoping middleware still requires local team membership**

   Trust tokens use `token_use="trusted"`, but `TokenScopingMiddleware` only gives special handling to `token_use="session"`:

   - `mcpgateway/middleware/token_scoping.py:1322-1336`

   Every other token is treated like an API/legacy token. When mapped teams are present, it validates them against local `email_team_members`:

   - `mcpgateway/middleware/token_scoping.py:1345-1361`

   Trust-only Entra principals intentionally have no such membership rows.

   Whether this is reached depends on middleware configuration and whether an earlier component cached the external payload, but once external authentication is consistently wired through middleware this becomes a concrete failure.

   **Runtime consequence:** a correctly mapped Entra user can receive:

   ```text
   403 Token is invalid: User is no longer a member of the associated team
   ```

4. **The acceptance tests do not exercise the claimed end-to-end behavior**

   The test described as the full group-role flow in `tests/unit/mcpgateway/test_trust_role_merge.py:220-252` does not make an HTTP request:

   - It patches `verify_jwt_token_cached`.
   - It calls `get_current_user()` directly.
   - It invokes `_check_agent_access()` directly.
   - It derives permissions manually from `user.roles`.
   - It never executes `get_current_user_with_permissions()` or `@require_permission`.

   The external-token dispatch matrix at `tests/unit/mcpgateway/test_token_dispatch_matrix.py:271-305` calls `_maybe_verify_external()` directly instead of sending the token through `get_current_user()`.

   This misses both primary blockers above.

   Issue #6272 explicitly requires:

   ```text
   POST /a2a/agent-a/invoke -> 200
   ```

   No test in the stack demonstrates that result through the real route, authentication dependency, middleware, RBAC decorator, visibility check, and downstream invocation.

5. **The mandatory live validation gate was not run**

   Issue [#5906](https://github.com/IBM/mcp-context-forge/issues/5906) states:

   > Do not declare done with any gate red or any matrix row untested.

   PR #6755 explicitly reports that:

   - The production-style Docker stack was not started.
   - `make test-mcp-protocol-e2e test-mcp-rbac` did not run against a gateway.
   - All 40 relevant tests self-skipped because no gateway was reachable.

   GitHub currently exposes only a successful DCO check on the stack-tip PR, not the claimed CI/live-gateway validation.

6. **The migration stack conflicts with current `main`**

   Current `main` has Alembic head:

   ```text
   5e211ec89cad
   ```

   The proposed canonical-ID migration starts from the older revision:

   - `mcpgateway/alembic/versions/bf2998718ea1_add_user_id_to_email_users.py:23`
   - `down_revision = "12d4a0c7789c"`

   The trust stack then continues to `f7a8b9c0d1e2`.

   Merging the stack as-is creates multiple Alembic heads. The stack is also 25 commits from a common ancestor while current `main` is independently 15 commits ahead, with extensive overlapping files.

   **Runtime/deployment consequence:** the migrations cannot be merged and deployed unchanged.

7. **The #5884 canonical-ID writer design conflicts with existing foreign keys**

   PR #6735 changes role and team-membership writers to store the canonical opaque `user_id` in columns named `user_email`. Those columns still reference `email_users.email`:

   - `UserRole.user_email`: `mcpgateway/db.py:1263`
   - `EmailTeamMember.user_email`: `mcpgateway/db.py:2128`

   The new canonical ID is stored separately:

   - `EmailUser.user_id`: `mcpgateway/db.py:1522`

   For a user such as:

   ```text
   email = alice@example.com
   user_id = <opaque Entra subject>
   ```

   writing the opaque subject into `UserRole.user_email` or `EmailTeamMember.user_email` violates the existing foreign key.

   The proposed tests use SQLite without the production foreign-key enforcement setup, so they do not expose this failure.

   This is less central to the trust-only path, which deliberately avoids local users, but it makes issue #5884 itself unsafe to merge and can break DB-backed users after the combined stack lands.

8. **Canonical identity is also dropped from the normal RBAC request context**

   The same `get_current_user_with_permissions()` response that drops roles also drops `user_id`. Consequently, `get_user_id(user_context)` falls back to the e-mail attribute.

   Thus #5884's stored canonical ID does not reliably reach live REST/RPC RBAC checks even after its schema and writers are merged.

9. **Required feature flags are not wired into the default Compose deployment**

   The Entra trust path requires both:

   ```text
   JWT_TRUST_MODE=jwt-trust
   SSO_API_TOKEN_AUTH_ENABLED=true
   ```

   The stack documents these settings, but neither `docker-compose.yml` nor `docker-compose.sso.yml` passes them into the gateway's explicit environment list.

   The Helm chart can receive arbitrary secret values, so custom Kubernetes deployment is possible, but the repository's Compose-based validation environment will not activate the intended path as currently defined.

**Non-Blocking Concerns**

- `is_admin = bool(claim)` in `mcpgateway/utils/trusted_claims.py:352` interprets any non-empty string, including `"false"`, as administrator access. This becomes a critical privilege-escalation risk if an issuer emits string-valued claims.
- `JWT_CLAIM_TEAMS=groups` can place raw Entra group GUIDs directly into `teams` before mapping. Configuration should prevent the group claim from also being treated as a native ContextForge team claim.
- The external identity cache is keyed only by token hash, without the trust mode or mapping version. Mode switches and mapping deletion can leave stale authorization until cache expiry.
- The mapping table's uniqueness constraint includes nullable `tenant`. SQLite and PostgreSQL permit multiple rows with `NULL` in an ordinary unique constraint, weakening the stated one-group-to-one-team rule.
- The mapping CRUD's Graph validator is still a disabled stub in `mcpgateway/routers/admin_external_group_mappings.py:51-71`; PR #5977 did not wire a real validator into it.
- Role lookup is name-based while role uniqueness is scoped. Duplicate role names across scopes can union more permissions than intended.
- Entra group-overage tokens default to `fail_closed`. Supporting users with large memberships requires `jwt_trust_overage_policy=graph_lookup` and separate Microsoft Graph client credentials. That is relevant to end-user tokens even though service-principal invocation itself is outside this review.
- The same token remains unsupported on the global `/mcp` transport because it uses a separate issuer/OAuth routing path. This does not block `/a2a/.../invoke` specifically, but contradicts an “all requests arrive with Entra tokens” deployment model.

**What Is Still Needed**

1. Rebase the entire #5884/#5885 stack onto current `main` and update the Alembic ancestry to preserve a single migration head.
2. Change `get_current_user()` and every relevant authentication choke point to use the external-aware verifier for Entra bearers, while preserving issuer, audience, JWKS, revocation, and fail-closed behavior.
3. Carry `user_id`, `roles`, and the claims-derived administrator value from `VirtualPrincipal` into `get_current_user_with_permissions()`.
4. Pass `token_roles` and `token_is_admin` from the RBAC decorator into `PermissionService`.
5. Teach `TokenScopingMiddleware` that `token_use="trusted"` teams came from the verified group-mapping resolver and must not be checked against `email_team_members`.
6. Fix #5884's relational design: do not write opaque canonical IDs into columns whose foreign keys still reference `email_users.email`. Either migrate those columns/FKs to a canonical key or use a separate stable internal identity relation.
7. Add strict claim-type validation, especially for the admin claim.
8. Wire both required environment variables into the supported Compose deployment and document the complete provider setup.
9. Add a real black-box test that:
   - Starts ContextForge in trust mode.
   - Configures a trusted Entra-compatible OIDC issuer and audience.
   - Creates Agent-A's ContextForge team.
   - Registers Agent-A with `visibility="team"` and that team.
   - Maps an Entra group object ID to the team and `developer`.
   - Sends a genuinely externally signed user token to `POST /a2a/Agent-A/invoke`.
   - Asserts mapped user `200`, unmapped user `403` or `404`, wrong audience `401`, missing revocation claim `401`, and no `email_users` access.
10. Run the mandatory production-style, protocol, RBAC, migration, SQLite-FK, and PostgreSQL validation gates without skipped tests.

**Evidence Status**

- **Verified:** current `main` and the complete stack-tip source paths, issue/PR states, Alembic heads, missing runtime propagation, disconnected tests, absent Compose wiring, and PR #6755's skipped live validation.
- **Inferred from verified code:** exact post-ingress failures in RBAC and token scoping, because no real Entra-backed stack was available to execute.
- **Not verified:** author-reported full-suite results, real Entra tenant behavior, Microsoft Graph consent/throttling behavior, PostgreSQL migration cycles, and multi-worker revocation. The PRs do not provide completed live-stack evidence for these.
