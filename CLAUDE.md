# FVC Bridge — CLAUDE.md

## What FVC is
**FVC = findvancouverclinics.com** — a WordPress + GeoDirectory directory of Vancouver health clinics (physiotherapy, chiropractic, massage, naturopath, acupuncture). Hosted on SiteGround. Custom logic runs via the WPCode plugin and this bridge plugin.

## What this repo is
The **FVC Bridge** WordPress plugin — a token-authenticated REST bridge + self-update channel that lets Claude manage the live site **without** wp-admin, FTP, or database logins. It owns the clinic add/claim form handlers and can publish approved submissions into live listings.

## Folder layout
- `fvc-bridge.php` — the entire plugin (single file).
- `build.ps1` — packages `build/fvc-bridge.zip` (forward-slash entries, root folder `fvc-bridge/`) + `build/manifest.json`.
- `wp-snippets/` — reference copies of the WPCode form handlers (superseded by the bridge; kept for history).
- `build/` — generated artifacts (gitignored).

## Endpoints (`/wp-json/fvc-bridge/v1/`)
- `GET /health` — version + status. `POST /self-update` — pull latest release.
- `GET /inspect-listing` — anatomy of an existing listing. `GET /submissions?status=new` — the submission queue.
- `POST /check-duplicate` (public, rate-limited) — dedup check for the form.
- `POST /create-listing` — publish an **approved stored submission BY ID** (never arbitrary content); idempotent.
All except `/check-duplicate` require `Authorization: Bearer <token>`. Tokens are stored as SHA-256 hashes in WP options and compared with `hash_equals`; per-IP and per-token rate limits; every privileged call is audit-logged.

## Build & deploy (the loop)
1. Edit `fvc-bridge.php`; **bump the `Version:` header AND `FVC_BRIDGE_VERSION`**.
2. `php -l fvc-bridge.php` (must be clean).
3. `powershell -ExecutionPolicy Bypass -File build.ps1`.
4. **Verify the zip** (WordPress mis-installs bad zips): confirm entries are under `fvc-bridge/` with forward slashes and include `fvc-bridge/fvc-bridge.php` (use Python `zipfile`, not just Compress-Archive).
5. `gh release create vX.Y.Z build/fvc-bridge.zip build/manifest.json --repo rubenjdelacruz1985-jpg/fvc-bridge --title vX.Y.Z --notes "..."`.
6. `POST /self-update` with the token, then `GET /health` — confirm the live site reports the new version.

## Hard rules
- **No secrets in code, commits, or reports.** API keys live in `wp-config.php` constants (e.g. `FVC_BREVO_API_KEY`), set by Ruben in wp-admin. Bridge tokens live only as hashes in WP options. The manager token lives in `C:\fvc-pipeline\.env` — read it there, never print it.
- **No direct WordPress-database writes from tooling/scripts** to work around the bridge. All site changes go through the bridge's audited endpoints. (The plugin's own `$wpdb` calls are the exception — that's its job.)
- **Do NOT build a remote key-setter endpoint.** Secrets are set in wp-admin by Ruben only.
- **CASL:** marketing/Brevo add only with explicit `marketing_consent`; transactional emails include sender identity + address.
- **No test emails to real clinic addresses** — during testing use Ruben's own address only.
- No force-push, no deleting listings or data.
- This repo has nothing to do with `C:\Users\ruben\projects\lead-engine` — never put FVC files there.

## Note on repo visibility
The GitHub repo is **public** because WordPress self-update downloads the release zip, and GitHub release assets on a private repo require auth. The plugin contains **no secrets**, so public is safe. Making it private would break self-update unless authenticated release fetching is added first.
