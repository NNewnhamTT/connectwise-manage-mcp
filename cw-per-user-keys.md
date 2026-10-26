# One ConnectWise key per person

By default the whole team shares one ConnectWise API member (`CW_MANAGE_*`), so ConnectWise's own audit trail shows one actor, and every person's Claude has that member's permissions. Per-user mode gives each person's calls that person's own ConnectWise API key, held on the server and chosen by who is signed in.

What you get (what the code does, tested with a stubbed ConnectWise):
- Calls use the signed-in person's own key. The shared key is never used in this mode.
- A person with no key on file is refused on every tool, reads included. Nothing reaches ConnectWise. The audit log records `denied` with reason `no-cw-key`. There is no fallback to a shared key.
- PII tokens are separate per person (the token namespace follows the key), so one person cannot use another's tokens.
- Each audit line carries `"credential":"per-user"`. A key is never logged.

What depends on ConnectWise: **confirmed (2026-10-23, by the maintainer):** a note added to a ticket through the MCP with a personal key shows that person's own user account in ConnectWise's audit trail. **Not yet verified:** the same for field changes and time entries, `_info.updatedBy` and `enteredBy`, how rate limits apply per key, and exactly what a personal key may do. See the checklist at the end. Do the rest on a sandbox or a harmless test ticket before you rely on it.

## 1. Create a key for each person in ConnectWise

The person creates their own key (as of 2026-10-23, from third-party vendor guides; ConnectWise's own docs were behind a login, so check the menu names in your Manage):
1. An administrator allows API keys for the person's security role: the role must permit **API Keys** (My Account section).
2. The person opens **System > My Account > API Keys** and adds a key. A description such as `Claude MCP` helps.
3. Copy the **public key** and the **private key**. The private key is shown only once.

A personal key has **that person's security role**. Whatever the person can do in Manage, their Claude can do through this server (subject to `MCP_POLICY` and their role in the MCP). If that is more than you want, give the person a separate restricted ConnectWise API member instead and use its key. The server treats both the same way.

## 2. Add the keys to `.env`

```env
CW_CREDENTIALS=per-user
CW_USER_KEYS=nick@tektrendz.com=<public key>:<private key>;sam@tektrendz.com=<public key>:<private key>
CW_MANAGE_COMPANY_ID=<your CW company id>
CW_MANAGE_CLIENT_ID=<your clientId>
CW_MANAGE_PUBLIC_KEY=
CW_MANAGE_PRIVATE_KEY=
```

- **The name** before `=` is the person's identity as the server sees it, matched without regard to case: their **Entra sign-in name** when `PROXY_AUTH=entra`, or their **`PROXY_USERS` name** in token mode. The Entra name is the first of these claims that the token carries: `upn`, `unique_name`, `preferred_username`, `sub`. With version 2 tokens that is normally `preferred_username`, usually the UPN, but it can differ for guest accounts. **To get the exact value, have the person sign in once and copy `user` from the audit line** (`docker logs cw-manage-mcp | grep '"type":"audit"' | tail -3`).
- **Keys** may not contain spaces or the characters `:` `;` `=`.
- **Shared keys** `CW_MANAGE_PUBLIC_KEY` and `CW_MANAGE_PRIVATE_KEY` stay empty. The server ignores them in this mode, and leaving them out removes a powerful key from the container.
- A bad value (unknown mode, an entry that cannot be read, a missing company id or client id, no entries at all) stops the server with a message that names the entry number and never repeats the key.
- Per-user mode works only with `AUTH_MODE=env` (the Docker stack). It cannot be combined with keys that clients send in headers (gateway mode): the server refuses to start a request that mixes them.
- `docker compose -f docker-compose.stack.yml --profile https up -d --build` applies a change (the container is recreated).

Where the keys live: in `.env` on the Docker machine, and in the container's environment. Anyone who can run `docker inspect` there, or read `.env`, can read every key. Limit who has access to that machine. Never commit `.env`.

## 3. Add, rotate and remove a person

- **Add:** create the key (step 1), add one entry to `CW_USER_KEYS`, run `up -d`.
- **Rotate:** create a new key in ConnectWise, replace the entry, run `up -d`, then delete the old key in ConnectWise.
- **Remove:** delete the person's key in ConnectWise and their entry in `CW_USER_KEYS`, run `up -d`. Removing the entry alone makes the server refuse them. Deleting the key alone makes ConnectWise refuse the calls.
- A person with a role in Entra but no entry is refused: signing in does not create a key.

## 4. Check it

1. Sign in as a person with a key. Ask for a ticket. In `docker logs cw-manage-mcp` the audit line shows `"credential":"per-user"` and their name as `user`.
2. Sign in as a person with no entry. Every call should come back with `No ConnectWise key is on file for "<name>"`, and the audit line shows `"reason":"no-cw-key"`.
3. Confirm the shared key is gone from use: with `CW_MANAGE_PUBLIC_KEY` empty, the first check still works.

## 5. Sandbox checklist (not done yet)

On a test ticket, as a person with a personal key, check in ConnectWise itself:
- [x] The ticket's **audit trail** (history) names the person, not a shared API member, for a **note** added through Claude (confirmed 2026-10-23).
- [ ] The same for a **field you change** through Claude (for example the priority).
- [ ] `_info.updatedBy` and note `createdBy` show the person.
- [ ] A time entry made through Claude is attributed to the person.
- [ ] A person whose ConnectWise role is read-only cannot change anything through Claude, whatever `MCP_POLICY` says.
- [ ] Delete the key in ConnectWise: the next call fails with a ConnectWise 401, and the error reaches Claude without a key or response body in it.
- [ ] Rate limit: note whether two people calling at once throttle each other (per key or per company).

Record the results in the knowledge base (`Automations\secure-cw-manage-mcp.md`).

## Limits

- One server process holds the PII token map, as before. More than one copy needs a shared store (not built).
- The ticket-card app and the stdio transport are not covered: stdio has no signed-in person, so per-user mode refuses it.
- The server picks a key by name only after the person has been identified (Entra token validated, or the proxy's signed header verified). A request that fails that check never reaches the key lookup.
