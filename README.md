# FVC Bridge

A tiny token-authenticated REST bridge + self-update channel for the Find Vancouver
Clinics WordPress site. After the first manual upload, every new version deploys itself.

## Endpoints (`/wp-json/fvc-bridge/v1/`)
- `GET /health` — returns plugin version, WP/PHP versions, and whether an update is available.
- `POST /self-update` — pulls the latest release and upgrades the plugin in place.

All endpoints require `Authorization: Bearer <token>`. Tokens are generated in
**Settings → FVC Bridge**, stored as SHA-256 hashes, revocable, and per-IP rate-limited.

## Self-update mechanism
- The plugin's `Update URI:` header points at this repo, so WordPress routes update
  checks through the `update_plugins_github.com` filter.
- That filter reads `manifest.json` from the **latest** GitHub release and offers the
  update **only** if the package URL is under
  `https://github.com/rubenjdelacruz1985-jpg/fvc-bridge/releases/download/` (pinned).
- `POST /self-update` runs WordPress's own `Plugin_Upgrader`.

## Release flow (from this PC)
1. Edit `fvc-bridge.php`, bump the `Version:` header.
2. `php -l fvc-bridge.php`  (lint)
3. `powershell -File build.ps1`  (creates `build/fvc-bridge.zip` + `build/manifest.json`)
4. `gh release create vX.Y.Z build/fvc-bridge.zip build/manifest.json --repo rubenjdelacruz1985-jpg/fvc-bridge --title vX.Y.Z --notes "..."`
5. `POST /self-update` → live in seconds; response reports `from`→`to`.

## One-time setup
- Upload `build/fvc-bridge.zip` once via **wp-admin → Plugins → Add New → Upload**.
- Generate a manager token in **Settings → FVC Bridge**.
- If the Authorization header is stripped by the host, add to `.htaccess`:
  ```
  RewriteEngine On
  RewriteCond %{HTTP:Authorization} ^(.*)
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%1]
  ```
