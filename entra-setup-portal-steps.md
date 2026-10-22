# Entra sign-in for the Docker stack: portal steps

Microsoft Entra ID sign-in for `docker-compose.stack.yml`. People sign in with their work account, and the audit log names them by their Entra sign-in name (`upn`). This replaces the per-person tokens in `PROXY_USERS`.

This guide extends `entra-app-registration.md` (the upstream guide) with three changes for this stack: the Claude Code redirect, three app roles instead of one, and assignment hardening. Do the steps in the Azure portal (as of 2026-10-22, menu names can move).

You need the Application Administrator (or Global Administrator) role.

## What you end up with

| App role | Value | Access in the MCP |
|---|---|---|
| CWM Access | `CWM.Access` | Read tools (`MCP_POLICY=read` level) |
| CWM Write | `CWM.Write` | Read and write tools |
| CWM Admin | `CWM.Admin` | Read, write and delete tools |

Assign **one** role per person. `CWM.Write` and `CWM.Admin` also grant sign-in, so nobody needs `CWM.Access` as well. A role assigned to a person overrides the server's `MCP_POLICY` default, up or down.

## 1. Register the app

1. **Microsoft Entra ID** > **App registrations** > **New registration**.
2. Name: `CWM-MCP-Server`. Supported account types: **this organizational directory only (single tenant)**. Leave the redirect URI blank. **Register**.
3. On **Overview**, copy **Application (client) ID** and **Directory (tenant) ID**. They go into `.env` (step 9).

## 2. Redirect URIs (Mobile and desktop applications)

1. **Authentication** > **Add a platform** > **Mobile and desktop applications**.
2. Under **Custom redirect URIs**, add both:
   - `http://localhost/callback` for Claude Code. Claude Code uses `http://localhost:<random port>/callback`. Entra ignores the port on a localhost redirect and matches the path exactly, so this one entry covers every port (Microsoft Learn, *Redirect URI best practices*).
   - `https://claude.ai/api/mcp/auth_callback` for claude.ai on the web, later.
3. **Configure**.

If the portal refuses the `http://localhost/callback` entry, open **Manifest** and add this to `replyUrlsWithType`, then save:

```json
{ "url": "http://localhost/callback", "type": "InstalledClient" }
```

Do not register the entries under **Web** or **Single-page application**.

## 3. Public client flows

On **Authentication** > **Advanced settings**, set **Allow public client flows** to **Yes**, then **Save**.

## 4. Token version

**Manifest**: next to `signInAudience`, set `"accessTokenAcceptedVersion": 2` (the number 2, not the string). **Save**, then reopen the manifest and check that it stuck.

## 5. Expose an API

1. **Expose an API** > **Application ID URI** > **Add** > accept `api://<client-id>` > **Save**.
2. **Add a scope**: name `access_as_user`, who can consent **Admins and users**, display name `Access CWM MCP Server`, description `Allows the user to call the ConnectWise Manage MCP tools`, state **Enabled**.

## 6. Create the three app roles

**App roles** > **Create app role**, three times. Allowed member types: **Users/Groups**. Enable each.

| Display name | Value | Description |
|---|---|---|
| CWM Access | `CWM.Access` | Read access to the ConnectWise Manage MCP tools |
| CWM Write | `CWM.Write` | Read and write access to the ConnectWise Manage MCP tools |
| CWM Admin | `CWM.Admin` | Read, write and delete access to the ConnectWise Manage MCP tools |

The values are case-sensitive. The server looks for these exact strings.

## 7. API permissions

**API permissions**: confirm Microsoft Graph delegated `openid`, `profile` and `email`, then **Grant admin consent for \<tenant\>**.

## 8. Require assignment, then assign people

1. **Enterprise applications** > `CWM-MCP-Server` > **Properties** > **Assignment required?** = **Yes** > **Save**. Without this, anyone in the tenant can get a token for the app (the server would still refuse them, because the token carries no role, but they would get past Entra).
2. **Users and groups** > **Add user/group**. Pick a person and **one** role. Repeat per person.
3. Assigning a security group instead of people needs Entra ID P1 (unverified for this tenant). If assigning to groups works, use one group per role.

Role changes take effect at the person's next sign-in (new token).

## 9. Settings in `.env` on the Docker machine

Placeholders: replace everything in angle brackets.

```env
PROXY_AUTH=entra
MCP_OAUTH_ENABLED=true
MCP_SERVER_URL=https://<MCP_HOSTNAME>
AZURE_TENANT_ID=<Directory (tenant) ID>
AZURE_CLIENT_ID=<Application (client) ID>
AZURE_AUDIENCE=api://<Application (client) ID>
AZURE_REQUIRED_ROLE=CWM.Access
```

`MCP_SERVER_URL` must be exactly the address people connect to, starting with `https://`, with no trailing slash. The server advertises it during sign-in.

## 10. HTTPS with Caddy and Cloudflare DNS

Entra sign-in needs an HTTPS address. Caddy gets its certificate by the DNS challenge, so **no inbound port has to be open for the certificate**: Caddy only calls the Cloudflare API to write a DNS TXT record.

1. The domain's DNS must be in Cloudflare. Create a DNS record for the host name (`<MCP_HOSTNAME>`):
   - Type **A**, value = the Docker machine's address that your people can reach, proxy status **DNS only** (grey cloud).
   - A private LAN address works if people are on the LAN or a VPN. It makes that internal address visible in public DNS.
2. Create an API token: Cloudflare dashboard > **My Profile** > **API Tokens** > **Create Token**. Permissions: **Zone / Zone / Read** and **Zone / DNS / Edit**, limited to that one zone. (Permissions per the caddy-dns/cloudflare README.) Copy it once.
3. In `.env`:

```env
MCP_HOSTNAME=<MCP_HOSTNAME>
CF_API_TOKEN=<the Cloudflare token>
HTTPS_BIND=0.0.0.0
```

4. Start the stack with the HTTPS profile:

```bash
docker compose -f docker-compose.stack.yml --profile https up -d --build
```

Everyone who signs in needs a network path to the Docker machine on port 443. claude.ai on the web connects from the internet, so it needs a public path (a Cloudflare Tunnel or the ACA deployment), not just a LAN address.

## 11. Connect and test

From a workstation:

```bash
curl https://<MCP_HOSTNAME>/.well-known/oauth-protected-resource
claude mcp add --transport http cw-pii https://<MCP_HOSTNAME>/mcp
```

The curl should return JSON naming `https://<MCP_HOSTNAME>` as the resource. In Claude Code, run `/mcp`, pick `cw-pii` and choose **Authenticate**. A browser opens for the Entra sign-in. After sign-in, ask for a ticket. Then check the audit line on the Docker machine:

```bash
docker logs cw-manage-mcp | grep '"type":"audit"' | tail -3
```

It should show `"source":"entra"` and the person's sign-in name as `user`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `AADSTS50011` redirect URI mismatch | `http://localhost/callback` missing, or added under Web or SPA. Re-add under Mobile and desktop applications. |
| `AADSTS65001` or `AADSTS50105` | The person has no role assigned (step 8). |
| 403 "missing required role" | Token has no `CWM.Access`, `CWM.Write` or `CWM.Admin`. Assign a role, then sign out and in (`/mcp` > Authenticate). |
| 401 "Invalid token", log shows `tokenAudience=...` | `AZURE_AUDIENCE` differs from the logged audience. Set it to exactly that value. |
| Sign-in works, writes are blocked | Expected: the person has `CWM.Access` (read) or `MCP_POLICY=read`. Assign `CWM.Write`. |
| Role change not applied | The old token is still valid. Sign out and sign in again. |
| Certificate not issued | `docker logs cw-caddy`. Check `CF_API_TOKEN` permissions and that the zone is in that Cloudflare account. |
