# Amir Virus

A self-hosted VLESS-over-WebSocket proxy with a hardened admin panel — one
Cloudflare Worker, one KV namespace, free plan.

## Files

- `worker.js` — the entire worker: admin panel, hardened auth, subscription generator, deep radar scanner, and the VLESS proxy core.
- `wrangler.toml` — deployment config.

## Setup

1. **Install Wrangler**, if you don't have it:
   ```
   npm install -g wrangler
   wrangler login
   ```
2. **Create the KV namespace**:
   ```
   npx wrangler kv namespace create VIRUS_PROXY_KV
   ```
   Copy the returned `id` into `wrangler.toml` under `kv_namespaces`.
3. Set your initial admin password in `wrangler.toml` under `[vars] ADMIN_PASS`
   (or leave the default and change it immediately from the panel).
4. **Deploy**:
   ```
   npx wrangler deploy
   ```
5. Visit `https://<your-worker>.workers.dev/admin`, log in, and immediately
   use "تغییر رمز عبور ادمین" to set a strong, unique password — this also
   invalidates your current session, so you'll need to log in again.
6. In **تنظیمات عمومی**, set `HOST`, `PATH`, `SNI`, and `FRAGMENT` to match
   your deployment and the client you'll be using.
7. Create users. Each user gets a **کپی لینک** (base64 VLESS link), a
   **Clash** YAML export, and a **QR code** button for scanning directly on
   mobile.
8. Use **Virus Radar** → "اسکن عمیق" to find the lowest-latency Cloudflare
   entry point *from your own network*, then tap "اعمال" to make it the new
   HOST in one step.

## What's genuinely better here than a typical public proxy panel

- **Hashed admin password.** The password is never stored in plain text —
  it's salted and SHA-256 hashed in KV, and verified with a constant-time
  comparison.
- **Login rate-limiting.** Five failed attempts locks out login for 15
  minutes, defeating brute-force password guessing against `/admin/login`.
- **Expiring sessions.** Admin tokens auto-expire after 24h instead of living
  forever in KV.
- **Daily quota, not just total quota.** Total lifetime quota alone doesn't
  stop someone from burning a month's worth of traffic in one day. Amir Virus
  tracks and auto-resets a separate daily cap per user.
- **Kill switch.** One checkbox takes every active and future connection
  offline immediately — no need to disable users one by one during an
  incident.
- **Deep radar with caching.** The scanner runs in concurrency-limited
  batches so it can safely probe a much larger pool of IPs (up to 300) than a
  naive "fire 50 requests at once" implementation, and it caches the last
  scan in KV so opening the panel doesn't force a rescan.
- **Built-in activity log viewer.** Every login (successful or failed),
  settings change, user action, and radar action is timestamped and visible
  right in the panel — no separate log tool needed.
- **QR codes for subscriptions.** No copy-pasting a long `vless://` link on a
  phone — scan it straight into the client.

## What it deliberately does NOT try to match

Being upfront about scope: this project supports **one protocol** (VLESS
over WebSocket + TLS) on purpose, to keep the codebase small enough that you
(or anyone) can actually read and audit all of it. It does not include:
Trojan/Shadowsocks/gRPC/XHTTP transports, a Telegram bot, WARP integration,
proxy chaining, or a D1 database backend. Larger public projects in this
space (e.g. Nova Proxy) cover more of that ground — if you need those
specific features, that's a reasonable thing to combine with this project
rather than something this worker tries to duplicate.

## Anti-censorship techniques (how they actually work here)

- **SNI spoofing** and **TLS fragmentation** are client-side behaviors. This
  worker only stores and exposes the `sni` and `fragment` values inside the
  subscription link; the connecting app (v2rayNG, NekoBox, sing-box,
  Clash-Meta, etc.) is what actually applies them.
- **ECH** support depends on both the client and Cloudflare's edge; the `ech`
  flag is exposed in the subscription params for clients that understand it.
- **"Clean IP" selection (Virus Radar)** works by probing a randomized sample
  of Cloudflare's own public edge IP ranges from wherever the admin runs the
  scan, and keeping the fastest responders. There's no private or special IP
  pool — it's the same public Cloudflare edge everyone uses, just measured
  from your own vantage point so the entry point suits your ISP.

## Security notes

- Change the default admin password immediately after first deploy.
- Every non-login `/admin/*` and `/radar/*` endpoint requires
  `Authorization: Bearer <session token>`, issued at login. Changing the
  password immediately invalidates the current session.
- UDP relaying is not implemented — only TCP (VLESS command `1`) is
  supported.
- Never paste your Cloudflare API token or GitHub token into a chat, issue,
  or commit message. If one is ever exposed, revoke it immediately and issue
  a new one — treat any token that has appeared in plaintext anywhere outside
  your own terminal as compromised.
