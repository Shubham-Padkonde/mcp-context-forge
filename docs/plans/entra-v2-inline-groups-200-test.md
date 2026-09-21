# Entra V2 Inline-Groups Access Tests

## Goal

Prove that ContextForge can process a real Microsoft Entra v2 end-user token with inline group GUIDs and enforce access to a team-visible A2A agent.

The four use cases are:

```text
USE CASE 1: The user's Entra group maps to the agent's CF team.
            -> The invocation succeeds with HTTP 200.

USE CASE 2: The user's Entra group maps to a different CF team.
            -> The invocation is hidden with HTTP 404 and never reaches the agent.

USE CASE 3: The user's Entra group maps to the agent's CF team with the viewer role. 
            -> The user can see the agent but invocation returns HTTP 403 and never reaches the agent.

USE CASE 4: The user's Entra group maps to the agent's ContextForge team. 
            However, the user belongs to too many groups and has a group overage. 
            -> *The invocation succeeds with HTTP 200 if JWT_TRUST_OVERAGE_POLICY=graph_lookup 
```
> I could not test Use Case 4 because I dont have any App Registration w Microsoft Graph ReadBasic.All and GroupMember.Read.All permissions.

> **Automation status:** `tests/live_gateway/test_trust_mode_entra_inline_groups_e2e.py` reproduces use cases 1 through 4 as live-gateway tests against a real Entra tenant (PR #6931). With `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` and `AZURE_TENANT_ID` exported, the harness provisions every identity. For use case 4 it provisions a user in 201 groups. It deletes every identity after the session. Each test skips when its Entra prerequisites are absent.

## Observed Result

Tested stack:

```text
commit: aae0b9707
```

Token metadata used by the test:

```text
v2 issuer
exact configured audience
oid present
uti present
23 inline group GUIDs
no group-overage marker
not expired
```

USE CASE 1 observed response:

```text
HTTP/1.1 200 OK
x-correlation-id: 61a3ddff242740439a4f70ec09c3b090

{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"TASK_STATE_COMPLETED"},"artifacts":[{"name":"response","parts":[{"text":"[Dummy Agent] Received your message: 'Hello from Entra trust-mode test'. This is a test agent for registry validation."}]}]}}
```

Correlated logs showed:

```text
external-idp trust authentication succeeded
token scoping used the mapped ContextForge team
RBAC context contained roles=["developer"]
PermissionService granted a2a.invoke
ContextForge called http://127.0.0.1:8001/a2a/
dummy agent handled a2a.message.send
downstream call returned 200
```

USE CASE 2 was then tested with the same token after changing its Entra-group mapping to a second ContextForge team that did not own the agent.

Observed response:

```text
HTTP/1.1 404 Not Found
x-correlation-id: e2772034be9945fcaf95f10df4fb1887

{"detail":"A2A Agent not found with name: dummy-a2a-agent"}
```

Correlated logs showed:

```text
external-idp trust authentication succeeded
token scoping used the second mapped ContextForge team
RBAC context contained roles=["developer"]
the team-visible agent was not visible to that team
ContextForge returned 404
no downstream A2A call was started
dummy agent did not receive the denied message
```

USE CASE 3 was then tested with the same token after changing its Entra-group mapping back to the agent's ContextForge team with `cf_role=viewer`.

Observed results:

```text
GET /a2a                           HTTP/1.1 200 OK
GET /a2a/<agent_id>                HTTP/1.1 200 OK
POST /a2a/dummy-a2a-agent/invoke   HTTP/1.1 403 Forbidden
x-correlation-id: 7b3b47269bcc4f5b943ac10fe59d2cce

{"detail":"Access denied"}
```

The list and read responses contained `dummy-a2a-agent`. Correlated invocation logs showed:

```text
token resolved to the agent's ContextForge team
RBAC context contained roles=["viewer"]
PermissionService denied a2a.invoke
ContextForge returned 403 from the RBAC decorator
the A2A service was not called
dummy agent did not receive the viewer message
```

## What This Proves

USE CASE 1 is a real Entra end-to-end success test through ContextForge:

```text
real Entra v2 token
  -> external OIDC/JWKS authentication
  -> inline Entra group GUID
  -> external_group_mappings
  -> ContextForge team
  -> ContextForge developer role
  -> a2a.invoke granted
  -> team-visible dummy agent lookup
  -> downstream A2A invocation
  -> 200
```

The epic works end to end for v2 tokens with inline groups, including the final downstream A2A call.

USE CASE 2 proves that access is fail-closed when the same authenticated user and role resolve to a team that does not own the agent:

```text
same real Entra v2 token
  -> external OIDC/JWKS authentication
  -> same inline Entra group GUID
  -> updated external_group_mappings row
  -> different ContextForge team
  -> ContextForge developer role
  -> a2a.invoke granted
  -> team-visible dummy agent filtered out
  -> no downstream A2A invocation
  -> 404
```

The `404` is intentional rather than `403`: it avoids revealing the existence of a team-private agent to a caller outside that team.

USE CASE 3 proves that visibility and invocation authorization are independently enforced:

```text
same real Entra v2 token
  -> external OIDC/JWKS authentication
  -> same inline Entra group GUID
  -> mapping restored to the agent's ContextForge team
  -> ContextForge viewer role
  -> a2a.read granted
  -> team-visible dummy agent listed and read
  -> a2a.invoke denied
  -> no downstream A2A invocation
  -> 403
```

## Repeatable Steps

### 0. Get the target App Registration ready

**It generates Entra V2t tokens**
![alt text](image-1.png)

**It exposes security groups**
![alt text](image.png)

> Note: I am using my adm account to get the token. The regular one belongs to too many groups. So the App Registration of the catalog would need to get the list of groups by calling Microsoft Graph and I had not granted it enough permisions for that.

### 1. Get a token

`python scripts/get_entra_token.py --acquire-user-token --output-file /home/basf/intelligent-automation/mcp-context-forge/entra-token-valid-v2.txt`

`TOKEN="$(tr -d '\r\n' < entra-token-valid-v2.txt)"`
I am using as Client ID the one of AI Suite; and the scope is the one of GraphChat.


**[OPTIONAL] Inspect the token without printing it**

```bash
.venv/bin/python -c '
import base64, json, sys, time
p = sys.argv[1].split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
groups = c.get("groups", [])
print(json.dumps({
    "iss": c.get("iss"),
    "aud": c.get("aud"),
    "tid": c.get("tid"),
    "has_oid": bool(c.get("oid")),
    "has_uti": bool(c.get("uti")),
    "groups_count": len(groups) if isinstance(groups, list) else 0,
    "first_group": groups[0] if isinstance(groups, list) and groups else None,
    "has_overage_marker": bool(c.get("hasgroups") or c.get("_claim_names")),
    "expired": not isinstance(c.get("exp"), int) or c["exp"] <= int(time.time()),
}, indent=2))
' "$TOKEN"
```

Requirements:

```text
groups_count > 0
has_overage_marker = false
expired = false
```

### 2. Start the local dummy A2A agent

Open a terminal and run:

```bash
cd /home/basf/intelligent-automation/gateway-mvp/dh-api-dummy-a2a-agent
source .venv/bin/activate
uvicorn api_dummy_a2a_agent.main:app --host 127.0.0.1 --port 8001
```

In another terminal, verify:

```bash
curl -sS http://127.0.0.1:8001/health
```

Expected:

```json
{"status":"OK"}
```

### 3. Start a local ContextForge gateway

```bash
rm -f /tmp/opencode/entra-inline-groups-200.db
```

Start ContextForge:

```bash
AUTH_REQUIRED=true \
MCPGATEWAY_A2A_ENABLED=true \
MCPGATEWAY_ADMIN_API_ENABLED=true \
SSO_ENABLED=true \
JWT_TRUST_MODE=jwt-trust \
SSO_API_TOKEN_AUTH_ENABLED=true \
JWT_TRUST_OVERAGE_POLICY=fail_closed \
JWT_TRUST_REVOCATION_CLAIM=uti \
JWT_CLAIM_USER_ID=oid \
JWT_CLAIM_TEAMS=teams \
LOG_LEVEL=DEBUG \
DEV_MODE=true \
SSRF_ALLOW_LOCALHOST=true \
SSRF_ALLOW_PRIVATE_NETWORKS=true \
DATABASE_URL='sqlite:////tmp/opencode/entra-inline-groups-200.db' \
JWT_SECRET_KEY='entra-inline-groups-jwt-secret-key-longer-than-thirty-two-characters' \
AUTH_ENCRYPTION_SECRET='entra-inline-groups-encryption-secret-longer-than-thirty-two-characters' \
BASIC_AUTH_PASSWORD='Entra-inline-basic-password-123!' \
PLATFORM_ADMIN_PASSWORD='Entra-inline-platform-password-123!' \
DEFAULT_USER_PASSWORD='Entra-inline-default-password-123!' \
ADMIN_REQUIRE_PASSWORD_CHANGE_ON_BOOTSTRAP=false \
PASSWORD_CHANGE_ENFORCEMENT_ENABLED=false \
.venv/bin/uvicorn mcpgateway.main:app --host 127.0.0.1 --port 8012
```

### 4. Set up the local ContextForge

#### 4.1 Generate a temporary setup token

In a second terminal:

```bash
export ADMIN_TOKEN="$(
  JWT_SECRET_KEY='entra-inline-groups-jwt-secret-key-longer-than-thirty-two-characters' \
  AUTH_ENCRYPTION_SECRET='entra-inline-groups-encryption-secret-longer-than-thirty-two-characters' \
  BASIC_AUTH_PASSWORD='Entra-inline-basic-password-123!' \
  PLATFORM_ADMIN_PASSWORD='Entra-inline-platform-password-123!' \
  DEFAULT_USER_PASSWORD='Entra-inline-default-password-123!' \
  PYTHONPATH=. .venv/bin/python -c '
from tests.helpers.auth import make_test_jwt
print(make_test_jwt(
    "admin@example.com",
    is_admin=True,
    secret="entra-inline-groups-jwt-secret-key-longer-than-thirty-two-characters",
    token_use="session",
))
' | tail -n 1
)"
```

This token is only for local setup. The tested A2A request uses only the Entra token.

#### 4.2 Extract non-secret mapping values

```bash
export ENTRA_TOKEN="$(tr -d '\r\n' < entra-token-valid-v2.txt)"

readarray -t ENTRA_VALUES < <(.venv/bin/python -c '
import base64, json, sys
p = sys.argv[1].split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print(c["iss"])
print(c["aud"][0] if isinstance(c["aud"], list) else c["aud"])
print(c["tid"])
print(c["groups"][0])
' "$ENTRA_TOKEN")

export ENTRA_ISSUER="${ENTRA_VALUES[0]}"
export ENTRA_AUDIENCE="${ENTRA_VALUES[1]}"
export ENTRA_TENANT_ID="${ENTRA_VALUES[2]}"
export TEST_EXTERNAL_GROUP_ID="${ENTRA_VALUES[3]}"
```

#### 4.3 Create the Entra trust root

For the inline-groups test, Graph credentials are not needed. Dummy client credentials are sufficient because token verification uses OIDC/JWKS and groups come from the token.

```bash
curl -i -X POST http://127.0.0.1:8012/auth/sso/admin/providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
    --arg issuer "$ENTRA_ISSUER" \
    --arg audience "$ENTRA_AUDIENCE" \
    '{
      id: "entra-inline-smoke",
      name: "entra-inline-smoke",
      display_name: "Entra Inline Groups Smoke",
      provider_type: "oidc",
      client_id: "unused-inline-test",
      client_secret: "unused-inline-test",
      authorization_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
      token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      userinfo_url: "https://graph.microsoft.com/oidc/userinfo",
      issuer: $issuer,
      scope: "openid profile email",
      trusted_domains: [],
      auto_create_users: false,
      team_mapping: {},
      provider_metadata: {groups_claim: "groups"},
      trusted_for_api_auth: true,
      api_audience: $audience
    }')"
```

Expected:

```text
HTTP/1.1 200 OK
```

### 5. Create the ContextForge team and mapping

#### 5.1 Create the ContextForge team

```bash
export CF_TEAM_ID="$(
  curl -sS -X POST http://127.0.0.1:8012/teams/ \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{
      "name":"Entra Inline Groups Agent Team",
      "description":"Inline groups real agent test",
      "visibility":"private"
    }' \
  | jq -er '.id'
)"

echo "ContextForge team ID: $CF_TEAM_ID"
```

#### 5.2 Map one real token group to the team and developer role

```bash
export MAPPING_ID="$(
  curl -sS -X POST http://127.0.0.1:8012/admin/external-group-mappings \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n \
      --arg issuer "$ENTRA_ISSUER" \
      --arg tenant "$ENTRA_TENANT_ID" \
      --arg group_id "$TEST_EXTERNAL_GROUP_ID" \
      --arg team_id "$CF_TEAM_ID" \
      '{
        issuer: $issuer,
        tenant: $tenant,
        external_group_id: $group_id,
        cf_team_id: $team_id,
        cf_role: "developer"
      }')" \
  | jq -er '.id'
)"

echo "External group mapping ID: $MAPPING_ID"
```

Expected:

```text
HTTP/1.1 200 OK
```

The mapping validator may report `validation_status=unknown` if dummy Graph credentials cannot validate the group. This does not block the mapping; the current contract is warn-and-allow. Graph is not used during authentication because the token contains inline groups.

### 6. Register the dummy agent in ContextForge

Register the running dummy agent with team visibility on the same team:

```bash
curl -i -X POST http://127.0.0.1:8012/a2a/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
    --arg team_id "$CF_TEAM_ID" \
    '{
      agent: {
        name: "dummy-a2a-agent",
        description: "Local dummy A2A agent",
        endpoint_url: "http://127.0.0.1:8001/a2a/",
        agent_type: "generic"
      },
      team_id: $team_id,
      visibility: "team"
    }')"
```

Expected:

```text
HTTP/1.1 201 Created
```

Verify the response contains:

```text
name: dummy-a2a-agent
enabled: true
reachable: true
visibility: team
teamId: <CF_TEAM_ID>
```

### 7. USE CASE 1: Invoke an agent the user can access

```bash
curl -i -X POST \
  http://127.0.0.1:8012/a2a/dummy-a2a-agent/invoke \
  -H "Authorization: Bearer $(tr -d '\r\n' < entra-token-valid-v2.txt)" \
  -H 'Content-Type: application/json' \
  -d '{
    "parameters": {
      "message": {
        "messageId": "entra-inline-1",
        "role": "user",
        "parts": [
          {"text": "Hello from Entra trust-mode test"}
        ]
      }
    },
    "interaction_type": "query"
  }'
```

Expected:

```text
HTTP/1.1 200 OK
```

The response contains a completed task and the dummy-agent echo:

```text
[Dummy Agent] Received your message: 'Hello from Entra trust-mode test'.
```

### 8. USE CASE 2: Deny access to an agent outside the user's mapped team

This case reuses the same real token. It creates a second team with no agents and updates the existing Entra-group mapping to point to that team. The dummy agent remains assigned to `$CF_TEAM_ID`.

#### 8.1 Create a team that does not own the agent

```bash
export NO_AGENT_TEAM_ID="$(
  curl -sS -X POST http://127.0.0.1:8012/teams/ \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{
      "name":"Entra Inline Groups No Agent Team",
      "description":"Mapped team without access to the dummy agent",
      "visibility":"private"
    }' \
  | jq -er '.id'
)"

echo "No-agent team ID: $NO_AGENT_TEAM_ID"
```

#### 8.2 Change the Entra-group mapping to the no-agent team

```bash
curl -i -X PUT \
  "http://127.0.0.1:8012/admin/external-group-mappings/$MAPPING_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
    --arg team_id "$NO_AGENT_TEAM_ID" \
    '{cf_team_id: $team_id}')"
```

Expected:

```text
HTTP/1.1 200 OK
```

Verify that the response still has `cf_role: developer` and now has:

```text
cf_team_id: <NO_AGENT_TEAM_ID>
```

The mapping update invalidates the external identity cache, so the same token is resolved against the new team on its next request.

#### 8.3 Invoke the same agent with the same Entra token

```bash
curl -i -X POST \
  http://127.0.0.1:8012/a2a/dummy-a2a-agent/invoke \
  -H "Authorization: Bearer $(tr -d '\r\n' < entra-token-valid-v2.txt)" \
  -H 'Content-Type: application/json' \
  -d '{
    "parameters": {
      "message": {
        "messageId": "entra-inline-denied",
        "role": "user",
        "parts": [
          {"text": "This request must not reach the dummy agent"}
        ]
      }
    },
    "interaction_type": "query"
  }'
```

Expected:

```text
HTTP/1.1 404 Not Found

{"detail":"A2A Agent not found with name: dummy-a2a-agent"}
```

The response is `404`, not `403`, because the user still has the `developer` role and therefore passes the `a2a.invoke` permission check. The agent lookup then hides the team-private agent because it belongs to `$CF_TEAM_ID`, while the token now resolves to `$NO_AGENT_TEAM_ID`.

Verify the dummy-agent logs do not contain:

```text
This request must not reach the dummy agent
```

This confirms that ContextForge rejected the request before making a downstream A2A call.

### 9. USE CASE 3: Allow agent visibility but deny invocation

This case reuses the same token and agent. It updates the existing Entra-group mapping back to the agent's team, but changes the role from `developer` to `viewer`. The built-in `viewer` role grants `a2a.read` but not `a2a.invoke`.

#### 9.1 Restore the mapping to the agent's team with the viewer role

```bash
curl -i -X PUT \
  "http://127.0.0.1:8012/admin/external-group-mappings/$MAPPING_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
    --arg team_id "$CF_TEAM_ID" \
    '{cf_team_id: $team_id, cf_role: "viewer"}')"
```

Expected:

```text
HTTP/1.1 200 OK
```

Verify that the response contains:

```text
cf_team_id: <CF_TEAM_ID>
cf_role: viewer
```

#### 9.2 List and read the visible agent with the same Entra token

```bash
curl -i http://127.0.0.1:8012/a2a/ \
  -H "Authorization: Bearer $(tr -d '\r\n' < entra-token-valid-v2.txt)"
```

Expected:

```text
HTTP/1.1 200 OK
```

The response includes `dummy-a2a-agent`. Copy its `id` to `AGENT_ID`, then verify direct read access:

```bash
export AGENT_ID='<agent ID from the list response>'

curl -i "http://127.0.0.1:8012/a2a/$AGENT_ID" \
  -H "Authorization: Bearer $(tr -d '\r\n' < entra-token-valid-v2.txt)"
```

Expected:

```text
HTTP/1.1 200 OK
```

#### 9.3 Attempt to invoke the visible agent with the same Entra token

```bash
curl -i -X POST \
  http://127.0.0.1:8012/a2a/dummy-a2a-agent/invoke \
  -H "Authorization: Bearer $(tr -d '\r\n' < entra-token-valid-v2.txt)" \
  -H 'Content-Type: application/json' \
  -d '{
    "parameters": {
      "message": {
        "messageId": "entra-inline-viewer",
        "role": "user",
        "parts": [
          {"text": "This viewer request must not reach the dummy agent"}
        ]
      }
    },
    "interaction_type": "query"
  }'
```

Expected:

```text
HTTP/1.1 403 Forbidden

{"detail":"Access denied"}
```

The request reaches neither agent lookup nor the downstream A2A call. The route's `a2a.invoke` RBAC check rejects the viewer role before the A2A service runs.

Verify the dummy-agent logs do not contain:

```text
This viewer request must not reach the dummy agent
```

## Conclusion

USE CASE 1 reaching `200` proves the complete epic success path works for a real Entra v2 token with inline groups:

```text
authentication passed
  + group-to-team mapping passed
  + group-to-role mapping passed
  + a2a.invoke authorization passed
  + team visibility passed
  + ContextForge invoked the registered downstream agent
  + dummy agent returned a successful response
```

USE CASE 2 reaching `404` with the same token after changing only the group-to-team mapping proves that ContextForge enforces agent team visibility:

```text
authentication still passed
  + group-to-team mapping changed to a team without the agent
  + group-to-role mapping still granted developer
  + a2a.invoke authorization still passed
  + team visibility hid the agent
  + no downstream call reached the dummy agent
```

USE CASE 3 proves that a user can see the agent but cannot invoke it when the group mapping retains the agent's team and assigns the `viewer` role:

```text
authentication passed
  + group-to-team mapping restored the agent's team visibility
  + viewer role granted a2a.read
  + agent list and direct read returned 200
  + viewer role did not grant a2a.invoke
  + invocation returned 403 before agent lookup or downstream call
```

## Potential Future Tests

The three inline-groups access cases above are proven. Complete these tests before broad production deployment:

1. **Real Entra group overage:** Use a token with an Entra group-overage marker and `JWT_TRUST_OVERAGE_POLICY=graph_lookup`. Confirm Microsoft Graph resolves a group mapped to the agent team and invocation role, then the agent invocation returns `200`. This remains unproven because the current test App Registration lacks the required Microsoft Graph application permissions/admin consent.
2. **Authentication deny matrix:** Confirm incorrect issuer, incorrect audience, expired token, missing configured user-ID claim (`oid` in this test), missing configured revocation claim (`uti` in this test), and a revoked `uti` each return `401`.
3. **Entra group lifecycle and cache behavior:** Add a user to the mapped Entra group and remove the user again. Obtain a new token after each change and confirm access is granted and withdrawn without stale group, identity, or mapping cache results.
4. **Multiple mapped groups:** Test one user with several Entra groups mapped to multiple ContextForge teams and roles. Cover an invocation role plus viewer role, and confirm access is granted only to agents in the user's resolved teams.
5. **Production deployment parity:** In the target Compose or Helm deployment, verify `JWT_TRUST_MODE=jwt-trust`, `SSO_API_TOKEN_AUTH_ENABLED=true`, exact issuer/audience provider configuration, Graph credentials for overage, and required outbound access to Entra JWKS and Microsoft Graph.
6. **Existing-database upgrade:** If deploying over an existing ContextForge database, test upgrading from the pre-Entra-trust stack. The migration compatibility concern in the investigation handoff remains unresolved.
7. **Entra app-only token**: Acquire a real client-credentials token. Verify expected identity claim mapping, exact audience/issuer, uti or configured revocation claim, roles-based authorization, and team visibility. Test both a permitted invocation and a denied invocation. If group-based team resolution is required, test JWT_TRUST_OVERAGE_POLICY=graph_lookup and service-principal group membership resolution.
8. **CF admin tests?**

It does not prove Entra v1 cross-origin JWKS support or Graph overage lookup. Those remain separate paths.
