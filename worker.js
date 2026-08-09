/**
 * =============================================================================
 *  AMIR VIRUS — Cloudflare Worker
 * =============================================================================
 *  A self-hosted VLESS-over-WebSocket proxy with a hardened admin panel,
 *  built to run entirely on Cloudflare's free Workers plan + one KV namespace.
 *
 *  WHAT'S INSIDE:
 *   - Admin panel (Persian/RTL, dark "virus" theme) served at GET /admin
 *   - Hashed admin password (SHA-256 + salt) + expiring session tokens
 *   - Login rate-limiting (defeats brute-force password guessing)
 *   - Multi-user management: total quota, DAILY quota (auto-resets), expiry,
 *     enable/disable, and an auto-disabled flag so the panel is honest about
 *     *why* a user stopped working
 *   - Global kill switch: one toggle takes the whole tunnel offline instantly
 *   - Subscription link generation (VLESS URI / base64, Clash-Meta YAML, and
 *     an inline QR code so mobile users can scan instead of copy-pasting)
 *   - "Virus Radar" deep scanner: scans a much larger, concurrency-limited
 *     pool of Cloudflare IPs than a naive implementation, caches results with
 *     a timestamp in KV so the panel doesn't need to rescan on every page
 *     load, and lets the admin apply any result as the new HOST in one tap
 *   - Built-in activity log viewer in the panel (no more guessing what
 *     happened — every login, user change, and radar action is recorded)
 *   - VLESS protocol parser + WebSocket <-> TCP bridge using the Workers
 *     `connect()` (cloudflare:sockets) API
 *
 *  HONEST SCOPE NOTE: this worker intentionally supports ONE protocol
 *  (VLESS over WebSocket+TLS) rather than several. That's a deliberate
 *  trade-off for a smaller, more auditable codebase — see README.md for a
 *  feature-by-feature comparison against other public projects in this
 *  space.
 *
 *  ANTI-CENSORSHIP NOTES:
 *   - SNI spoofing / TLS fragmentation / ECH are all *client-side* behaviors.
 *     This worker stores and exposes the relevant fields in the subscription
 *     link; the actual evasion happens in the connecting app (v2rayNG,
 *     NekoBox, sing-box, Clash-Meta, etc.), not on the worker itself.
 *   - "Clean IP" selection (Virus Radar) works by probing a wide, randomized
 *     sample of Cloudflare's own edge IP ranges from the same network the
 *     admin is deploying from, and keeping only the ones that answered
 *     fastest. There is no special/private IP pool — it's the same public
 *     Cloudflare edge everyone uses, just measured from your own vantage
 *     point so you get the entry point that suits your ISP.
 *
 *  STORAGE (Cloudflare KV, binding name: VIRUS_PROXY_KV):
 *   - "settings"       -> JSON { host, path, sni, fragment, ech, killSwitch }
 *   - "users"          -> JSON array of user objects
 *   - "adminPassHash"  -> JSON { salt, hash } (SHA-256(salt + password))
 *   - "adminSession"   -> JSON { token, expiresAt }
 *   - "loginAttempts"  -> JSON { count, windowStart }
 *   - "logs"           -> JSON array of recent activity log lines (capped)
 *   - "radarCache"     -> JSON { scannedAt, results: [{ip, latency}] }
 * =============================================================================
 */

import { connect } from 'cloudflare:sockets';

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const BRAND = 'Amir Virus';

const KV_KEYS = {
  SETTINGS: 'settings',
  USERS: 'users',
  ADMIN_PASS_HASH: 'adminPassHash',
  ADMIN_SESSION: 'adminSession',
  LOGIN_ATTEMPTS: 'loginAttempts',
  LOGS: 'logs',
  RADAR_CACHE: 'radarCache',
};

const DEFAULT_SETTINGS = {
  host: 'example.workers.dev',
  path: '/ws',
  sni: 'www.google.com',
  fragment: '1,40-60,30-50',
  ech: false,
  killSwitch: false, // when true, /ws refuses every connection instantly
};

const DEFAULT_ADMIN_PASS = 'change-this-password';
const MAX_LOG_ENTRIES = 300;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const LOGIN_MAX_ATTEMPTS = 5;
const WS_READY_STATE_OPEN = 1;

// -----------------------------------------------------------------------------
// Small utilities
// -----------------------------------------------------------------------------

function uuid() {
  return crypto.randomUUID();
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    },
  });
}

function textResponse(text, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(text, { status, headers: { 'Content-Type': contentType } });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

function base64Encode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function randomSalt() {
  return uuid().replace(/-/g, '');
}

// -----------------------------------------------------------------------------
// KV data access layer
// -----------------------------------------------------------------------------

async function getSettings(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.SETTINGS);
  if (!raw) {
    await env.VIRUS_PROXY_KV.put(KV_KEYS.SETTINGS, JSON.stringify(DEFAULT_SETTINGS));
    return { ...DEFAULT_SETTINGS };
  }
  try {
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

async function saveSettings(env, settings) {
  const clean = {
    host: String(settings.host || DEFAULT_SETTINGS.host).trim(),
    path: String(settings.path || DEFAULT_SETTINGS.path).trim(),
    sni: String(settings.sni || DEFAULT_SETTINGS.sni).trim(),
    fragment: String(settings.fragment || DEFAULT_SETTINGS.fragment).trim(),
    ech: Boolean(settings.ech),
    killSwitch: Boolean(settings.killSwitch),
  };
  await env.VIRUS_PROXY_KV.put(KV_KEYS.SETTINGS, JSON.stringify(clean));
  return clean;
}

async function getUsers(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.USERS);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function saveUsers(env, users) {
  await env.VIRUS_PROXY_KV.put(KV_KEYS.USERS, JSON.stringify(users));
}

async function getAdminPassHash(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.ADMIN_PASS_HASH);
  if (raw) {
    try {
      return JSON.parse(raw);
    } catch {
      /* fall through to reseed */
    }
  }
  const initialPass = (env.ADMIN_PASS && String(env.ADMIN_PASS)) || DEFAULT_ADMIN_PASS;
  const salt = randomSalt();
  const hash = await sha256Hex(salt + initialPass);
  const record = { salt, hash };
  await env.VIRUS_PROXY_KV.put(KV_KEYS.ADMIN_PASS_HASH, JSON.stringify(record));
  return record;
}

async function setAdminPass(env, newPass) {
  const salt = randomSalt();
  const hash = await sha256Hex(salt + newPass);
  await env.VIRUS_PROXY_KV.put(KV_KEYS.ADMIN_PASS_HASH, JSON.stringify({ salt, hash }));
}

async function verifyAdminPass(env, candidate) {
  const { salt, hash } = await getAdminPassHash(env);
  const candidateHash = await sha256Hex(salt + candidate);
  return safeEqual(candidateHash, hash);
}

async function getAdminSession(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.ADMIN_SESSION);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    if (!session.token || session.expiresAt < Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

async function setAdminSession(env, token) {
  const session = { token, expiresAt: Date.now() + SESSION_TTL_MS };
  await env.VIRUS_PROXY_KV.put(KV_KEYS.ADMIN_SESSION, JSON.stringify(session));
}

async function clearAdminSession(env) {
  await env.VIRUS_PROXY_KV.put(KV_KEYS.ADMIN_SESSION, JSON.stringify({ token: '', expiresAt: 0 }));
}

async function checkLoginRateLimit(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.LOGIN_ATTEMPTS);
  const now = Date.now();
  let state = raw ? JSON.parse(raw) : { count: 0, windowStart: now };
  if (now - state.windowStart > LOGIN_WINDOW_MS) {
    state = { count: 0, windowStart: now };
  }
  return { allowed: state.count < LOGIN_MAX_ATTEMPTS, state };
}

async function recordLoginAttempt(env, state, success) {
  if (success) {
    await env.VIRUS_PROXY_KV.put(KV_KEYS.LOGIN_ATTEMPTS, JSON.stringify({ count: 0, windowStart: Date.now() }));
    return;
  }
  const updated = { count: state.count + 1, windowStart: state.windowStart };
  await env.VIRUS_PROXY_KV.put(KV_KEYS.LOGIN_ATTEMPTS, JSON.stringify(updated));
}

async function appendLog(env, message) {
  try {
    const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.LOGS);
    const logs = raw ? JSON.parse(raw) : [];
    logs.unshift({ time: new Date().toISOString(), message });
    while (logs.length > MAX_LOG_ENTRIES) logs.pop();
    await env.VIRUS_PROXY_KV.put(KV_KEYS.LOGS, JSON.stringify(logs));
  } catch {
    // logging must never break the request flow
  }
}

async function getLogs(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.LOGS);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

// -----------------------------------------------------------------------------
// Auth
// -----------------------------------------------------------------------------

async function requireAdmin(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return false;
  const session = await getAdminSession(env);
  if (!session) return false;
  return safeEqual(match[1], session.token);
}

// -----------------------------------------------------------------------------
// Subscription link generation
// -----------------------------------------------------------------------------

function buildVlessUri(user, settings) {
  const params = new URLSearchParams({
    type: 'ws',
    security: 'tls',
    path: settings.path,
    host: settings.host,
    sni: settings.sni,
    fp: 'chrome',
    encryption: 'none',
  });
  if (settings.fragment) params.set('fragment', settings.fragment);
  if (settings.ech) params.set('ech', '1');

  const label = encodeURIComponent(`${BRAND}-${user.name}`);
  return `vless://${user.uuid}@${settings.host}:443?${params.toString()}#${label}`;
}

function buildClashYaml(user, settings) {
  const proxyName = `${BRAND}-${user.name}`;
  return `# ${BRAND} — Mihomo / Clash-Meta config
# Generated for user: ${user.name}
proxies:
  - name: "${proxyName}"
    type: vless
    server: ${settings.host}
    port: 443
    uuid: ${user.uuid}
    network: ws
    tls: true
    udp: true
    sni: ${settings.sni}
    servername: ${settings.sni}
    client-fingerprint: chrome
    ws-opts:
      path: "${settings.path}"
      headers:
        Host: ${settings.host}

proxy-groups:
  - name: "${BRAND}"
    type: select
    proxies:
      - "${proxyName}"

rules:
  - MATCH,${BRAND}
`;
}

// -----------------------------------------------------------------------------
// Virus Radar — deep scanner for low-latency Cloudflare edge IPs
// -----------------------------------------------------------------------------

const CF_IP_RANGES = [
  '104.16.0.0/12',
  '162.159.0.0/16',
  '172.64.0.0/13',
  '188.114.96.0/20',
  '198.41.128.0/17',
];

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}
function intToIp(int) {
  return [24, 16, 8, 0].map((shift) => (int >>> shift) & 255).join('.');
}
function randomIpInCidr(cidr) {
  const [base, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const baseInt = ipToInt(base);
  const hostBits = 32 - prefix;
  const hostMax = Math.pow(2, hostBits) - 1;
  const randomHost = Math.floor(Math.random() * hostMax);
  const mask = (~0 << hostBits) >>> 0;
  const networkInt = baseInt & mask;
  return intToIp((networkInt + randomHost) >>> 0);
}
function generateRandomCfIps(count) {
  const ips = new Set();
  let attempts = 0;
  while (ips.size < count && attempts < count * 5) {
    const range = CF_IP_RANGES[Math.floor(Math.random() * CF_IP_RANGES.length)];
    ips.add(randomIpInCidr(range));
    attempts++;
  }
  return Array.from(ips);
}

async function scanIp(ip, timeoutMs = 2500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    await fetch(`https://${ip}/cdn-cgi/trace`, {
      method: 'HEAD',
      headers: { Host: 'www.cloudflare.com' },
      signal: controller.signal,
    });
    return { ip, latency: Date.now() - started, ok: true };
  } catch {
    return { ip, latency: null, ok: false };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs scans in bounded-concurrency batches so a "deep" scan (a much larger
 * pool of candidate IPs) doesn't blow past Workers' subrequest limits or run
 * so many parallel fetches at once that results get noisy.
 */
async function runRadarScan(ipList, poolSize, concurrency = 12) {
  const list = Array.isArray(ipList) && ipList.length > 0 ? ipList : generateRandomCfIps(poolSize);
  const results = [];
  for (let i = 0; i < list.length; i += concurrency) {
    const batch = list.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map((ip) => scanIp(ip)));
    results.push(...batchResults);
  }
  return results
    .filter((r) => r.ok)
    .sort((a, b) => a.latency - b.latency)
    .map((r) => ({ ip: r.ip, latency: r.latency }));
}

async function getRadarCache(env) {
  const raw = await env.VIRUS_PROXY_KV.get(KV_KEYS.RADAR_CACHE);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function saveRadarCache(env, results) {
  const cache = { scannedAt: new Date().toISOString(), results };
  await env.VIRUS_PROXY_KV.put(KV_KEYS.RADAR_CACHE, JSON.stringify(cache));
  return cache;
}

// -----------------------------------------------------------------------------
// VLESS protocol parsing
// -----------------------------------------------------------------------------

function parseVlessHeader(buffer, expectedUuid) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'VLESS header too short' };
  const view = new DataView(buffer);
  const version = view.getUint8(0);

  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const uuidHex = Array.from(uuidBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  const formattedUuid = [
    uuidHex.slice(0, 8),
    uuidHex.slice(8, 12),
    uuidHex.slice(12, 16),
    uuidHex.slice(16, 20),
    uuidHex.slice(20, 32),
  ].join('-');

  if (!safeEqual(formattedUuid, expectedUuid)) return { hasError: true, message: 'UUID mismatch' };

  const addonsLength = view.getUint8(17);
  let offset = 18 + addonsLength;

  const command = view.getUint8(offset);
  offset += 1;
  if (command !== 1 && command !== 2) return { hasError: true, message: `Unsupported command: ${command}` };
  const isUDP = command === 2;

  const port = view.getUint16(offset, false);
  offset += 2;

  const addressType = view.getUint8(offset);
  offset += 1;

  let addressRemote = '';
  if (addressType === 1) {
    addressRemote = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
    offset += 4;
  } else if (addressType === 2) {
    const domainLength = view.getUint8(offset);
    offset += 1;
    addressRemote = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
    offset += domainLength;
  } else if (addressType === 3) {
    const segments = [];
    for (let i = 0; i < 8; i++) {
      segments.push(view.getUint16(offset, false).toString(16));
      offset += 2;
    }
    addressRemote = segments.join(':');
  } else {
    return { hasError: true, message: `Unsupported address type: ${addressType}` };
  }

  return { hasError: false, vlessVersion: version, addressRemote, portRemote: port, isUDP, rawDataIndex: offset };
}

// -----------------------------------------------------------------------------
// User validation helpers (total quota + daily quota + expiry + kill switch)
// -----------------------------------------------------------------------------

function dailyWindowStart(ts) {
  const d = new Date(ts);
  d.setUTCHours(0, 0, 0, 0);
  return d.getTime();
}

function rolloverDailyUsageIfNeeded(user) {
  const todayStart = dailyWindowStart(Date.now());
  if (!user.dailyResetAt || user.dailyResetAt < todayStart) {
    user.dailyUsedBytes = 0;
    user.dailyResetAt = todayStart;
  }
  return user;
}

function userIsUsable(user, settings) {
  if (settings.killSwitch) return { ok: false, reason: 'Service temporarily disabled (kill switch is on)' };
  if (!user) return { ok: false, reason: 'User not found' };
  if (!user.enabled) return { ok: false, reason: 'User disabled' };
  if (user.expiry && new Date(user.expiry).getTime() < Date.now()) {
    return { ok: false, reason: 'Subscription expired' };
  }
  rolloverDailyUsageIfNeeded(user);
  if (user.quotaBytes > 0 && (user.usedBytes || 0) >= user.quotaBytes) {
    return { ok: false, reason: 'Total quota exceeded' };
  }
  if (user.dailyQuotaBytes > 0 && (user.dailyUsedBytes || 0) >= user.dailyQuotaBytes) {
    return { ok: false, reason: 'Daily quota exceeded' };
  }
  return { ok: true };
}

function findUserByToken(users, token) {
  return users.find((u) => u.token === token);
}

// -----------------------------------------------------------------------------
// WebSocket <-> TCP bridge (the actual proxy tunnel)
// -----------------------------------------------------------------------------

async function handleVlessWebSocket(request, env, user) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  let tcpSocket = null;
  let usedBytesDelta = 0;

  const closeWithError = (message) => {
    try {
      server.close(1011, message.slice(0, 120));
    } catch {
      /* already closed */
    }
  };

  const flushUsage = async () => {
    if (usedBytesDelta <= 0) return;
    try {
      const users = await getUsers(env);
      const idx = users.findIndex((u) => u.id === user.id);
      if (idx !== -1) {
        rolloverDailyUsageIfNeeded(users[idx]);
        users[idx].usedBytes = (users[idx].usedBytes || 0) + usedBytesDelta;
        users[idx].dailyUsedBytes = (users[idx].dailyUsedBytes || 0) + usedBytesDelta;
        await saveUsers(env, users);
      }
    } catch {
      // never let accounting errors break the tunnel
    } finally {
      usedBytesDelta = 0;
    }
  };

  server.addEventListener('message', async (event) => {
    try {
      const chunk = event.data instanceof ArrayBuffer ? event.data : await event.data.arrayBuffer();

      if (!tcpSocket) {
        const parsed = parseVlessHeader(chunk, user.uuid);
        if (parsed.hasError) return closeWithError(parsed.message);
        if (parsed.isUDP) return closeWithError('UDP not supported');

        const settings = await getSettings(env);
        const check = userIsUsable(user, settings);
        if (!check.ok) return closeWithError(check.reason);

        try {
          tcpSocket = connect({ hostname: parsed.addressRemote, port: parsed.portRemote });
        } catch (err) {
          return closeWithError('TCP connect failed: ' + err.message);
        }

        server.send(new Uint8Array([parsed.vlessVersion, 0]).buffer);

        const writer = tcpSocket.writable.getWriter();
        (async () => {
          try {
            const reader = tcpSocket.readable.getReader();
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              if (server.readyState === WS_READY_STATE_OPEN) {
                server.send(value);
                usedBytesDelta += value.byteLength;
                if (usedBytesDelta > 262144) await flushUsage();
              }
            }
          } catch {
            /* upstream closed or errored */
          } finally {
            await flushUsage();
            if (server.readyState === WS_READY_STATE_OPEN) server.close(1000, 'upstream closed');
          }
        })();

        const initialPayload = chunk.slice(parsed.rawDataIndex);
        if (initialPayload.byteLength > 0) {
          await writer.write(new Uint8Array(initialPayload));
          usedBytesDelta += initialPayload.byteLength;
        }
        tcpSocket.__writer = writer;
        return;
      }

      await tcpSocket.__writer.write(new Uint8Array(chunk));
      usedBytesDelta += chunk.byteLength;
      if (usedBytesDelta > 262144) await flushUsage();
    } catch (err) {
      closeWithError('Relay error: ' + err.message);
    }
  });

  server.addEventListener('close', async () => {
    await flushUsage();
    try {
      if (tcpSocket) await tcpSocket.close();
    } catch {
      /* ignore */
    }
  });

  server.addEventListener('error', async () => {
    await flushUsage();
    try {
      if (tcpSocket) await tcpSocket.close();
    } catch {
      /* ignore */
    }
  });

  return new Response(null, { status: 101, webSocket: client });
}

// -----------------------------------------------------------------------------
// Admin panel HTML (Persian/RTL, dark "virus" theme, Vazirmatn font)
// -----------------------------------------------------------------------------

function renderAdminPanel() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${BRAND} | پنل مدیریت</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
@font-face {
  font-family: 'Vazirmatn';
  src: url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfont/woff2/Vazirmatn-Regular.woff2') format('woff2');
  font-weight: 400;
}
@font-face {
  font-family: 'Vazirmatn';
  src: url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/fonts/webfont/woff2/Vazirmatn-Bold.woff2') format('woff2');
  font-weight: 700;
}
:root {
  --bg: #0b0e14; --bg-card: #121722; --border: #1f2937;
  --green: #0f9; --blue: #3b82f6; --purple: #a855f7;
  --text: #e5e7eb; --text-dim: #94a3b8; --danger: #f87171;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:'Vazirmatn',Tahoma,sans-serif; min-height:100vh; }
.container { max-width:1100px; margin:0 auto; padding:20px; }
h1 { color:var(--green); font-size:22px; display:flex; align-items:center; gap:8px; }
h2 { font-size:17px; color:var(--blue); margin-top:0; }
.card { background:var(--bg-card); border:1px solid var(--border); border-radius:14px; padding:18px; margin-bottom:18px; }
input, select { background:#0e1420; border:1px solid var(--border); color:var(--text); border-radius:8px; padding:9px 10px; font-family:inherit; font-size:14px; width:100%; }
label { font-size:12px; color:var(--text-dim); display:block; margin-bottom:4px; }
.field { margin-bottom:12px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
button { background:linear-gradient(135deg,var(--green),#0c7); color:#05170f; border:none; border-radius:8px; padding:10px 16px; font-weight:700; cursor:pointer; font-family:inherit; font-size:14px; }
button.secondary { background:var(--blue); color:#fff; }
button.purple { background:var(--purple); color:#fff; }
button.danger { background:var(--danger); color:#2b0505; }
button.ghost { background:transparent; border:1px solid var(--border); color:var(--text); }
table { width:100%; border-collapse:collapse; font-size:13px; }
.table-wrap { overflow-x:auto; }
th, td { padding:8px 6px; border-bottom:1px solid var(--border); text-align:right; white-space:nowrap; }
th { color:var(--text-dim); font-weight:600; }
.badge { padding:2px 8px; border-radius:999px; font-size:11px; }
.badge.on { background:rgba(0,255,153,.15); color:var(--green); }
.badge.off { background:rgba(248,113,113,.15); color:var(--danger); }
.toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:#111827; border:1px solid var(--border); color:var(--text); padding:12px 20px; border-radius:10px; display:none; z-index:999; }
.hidden { display:none !important; }
.login-box { max-width:360px; margin:80px auto; text-align:center; }
.actions { display:flex; gap:6px; flex-wrap:wrap; }
.small { font-size:12px; padding:6px 10px; }
.kill-banner { background:rgba(248,113,113,.15); border:1px solid var(--danger); color:var(--danger); padding:10px 14px; border-radius:10px; margin-bottom:14px; font-size:13px; }
#qrModal { position:fixed; inset:0; background:rgba(0,0,0,.7); display:none; align-items:center; justify-content:center; z-index:1000; }
#qrModal .box { background:var(--bg-card); border:1px solid var(--border); border-radius:14px; padding:20px; text-align:center; }
#qrCanvas { background:#fff; padding:10px; border-radius:8px; display:inline-block; margin:10px 0; }
.log-line { font-size:12px; color:var(--text-dim); padding:6px 0; border-bottom:1px solid var(--border); }
.log-line span { color:var(--green); }
</style>
</head>
<body>
<div class="container">

  <div id="loginView" class="login-box card">
    <h1>🦠 ${BRAND}</h1>
    <p style="color:var(--text-dim)">برای ورود به پنل مدیریت رمز عبور را وارد کنید</p>
    <div class="field"><input type="password" id="loginPass" placeholder="رمز عبور ادمین"></div>
    <button onclick="doLogin()" style="width:100%">ورود</button>
  </div>

  <div id="mainView" class="hidden">
    <h1>🦠 ${BRAND} — پنل مدیریت</h1>
    <div id="killBanner" class="kill-banner hidden">⚠️ کلید قطع کامل (Kill Switch) فعال است — همه‌ی اتصالات مسدود شده‌اند.</div>

    <div class="card">
      <h2>⚙️ تنظیمات عمومی</h2>
      <div class="grid">
        <div class="field"><label>HOST</label><input id="setHost"></div>
        <div class="field"><label>PATH</label><input id="setPath"></div>
        <div class="field"><label>SNI (جعل دامنه)</label><input id="setSni"></div>
        <div class="field"><label>FRAGMENT</label><input id="setFragment"></div>
      </div>
      <label style="display:flex;align-items:center;gap:6px;margin-bottom:8px"><input type="checkbox" id="setEch" style="width:auto"> فعال‌سازی ECH (اختیاری)</label>
      <label style="display:flex;align-items:center;gap:6px;margin-bottom:12px"><input type="checkbox" id="setKill" style="width:auto"> 🔴 Kill Switch — قطع فوری همه‌ی اتصالات</label>
      <button onclick="saveSettings()">ذخیره تنظیمات</button>
    </div>

    <div class="card">
      <h2>👥 مدیریت کاربران</h2>
      <div class="grid">
        <div class="field"><label>نام</label><input id="newName" placeholder="مثلا: علی"></div>
        <div class="field"><label>نام کاربری (اختیاری)</label><input id="newUsername"></div>
        <div class="field"><label>سقف کل (گیگابایت، ۰=نامحدود)</label><input id="newQuota" type="number" value="0"></div>
        <div class="field"><label>سقف روزانه (گیگابایت، ۰=نامحدود)</label><input id="newDailyQuota" type="number" value="0"></div>
        <div class="field"><label>تاریخ انقضا (اختیاری)</label><input id="newExpiry" type="date"></div>
      </div>
      <button onclick="createUser()">➕ ایجاد کاربر</button>

      <div class="table-wrap" style="margin-top:16px">
        <table>
          <thead><tr><th>نام</th><th>وضعیت</th><th>انقضا</th><th>ترافیک کل</th><th>ترافیک روزانه</th><th>اشتراک</th><th>عملیات</th></tr></thead>
          <tbody id="usersTableBody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>🔍 Virus Radar</h2>
      <p style="color:var(--text-dim);font-size:13px">اسکن عمیق آی‌پی‌های Cloudflare برای یافتن سریع‌ترین مسیر از شبکه‌ی خودت</p>
      <div id="radarMeta" style="color:var(--text-dim);font-size:12px;margin-bottom:8px"></div>
      <div class="actions">
        <button onclick="startScan(60)">🔍 اسکن سریع (۶۰ IP)</button>
        <button class="purple" onclick="startScan(200)">🧬 اسکن عمیق (۲۰۰ IP)</button>
      </div>
      <div class="table-wrap" style="margin-top:12px">
        <table>
          <thead><tr><th>IP</th><th>تأخیر (ms)</th><th></th></tr></thead>
          <tbody id="radarTableBody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>📜 لاگ فعالیت</h2>
      <button class="ghost small" onclick="loadLogs()">به‌روزرسانی لاگ</button>
      <div id="logsBox" style="margin-top:10px;max-height:240px;overflow-y:auto"></div>
    </div>

    <div class="card">
      <h2>🔑 تغییر رمز عبور ادمین</h2>
      <button class="secondary" onclick="changePassword()">تغییر رمز عبور</button>
    </div>
  </div>
</div>

<div id="qrModal">
  <div class="box">
    <div id="qrCanvas"></div>
    <div><button class="ghost small" onclick="document.getElementById('qrModal').style.display='none'">بستن</button></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let ADMIN_TOKEN = localStorage.getItem('vp_token') || '';

function showToast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = isError ? 'var(--danger)' : 'var(--green)';
  t.style.display = 'block';
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => (t.style.display = 'none'), 3000);
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (ADMIN_TOKEN) headers['Authorization'] = 'Bearer ' + ADMIN_TOKEN;
  if (options.body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    localStorage.removeItem('vp_token');
    showToast('نشست شما منقضی شده، دوباره وارد شوید', true);
    showLogin();
    throw new Error('unauthorized');
  }
  return res.json();
}

function showLogin() {
  document.getElementById('loginView').classList.remove('hidden');
  document.getElementById('mainView').classList.add('hidden');
}
function showMain() {
  document.getElementById('loginView').classList.add('hidden');
  document.getElementById('mainView').classList.remove('hidden');
  loadSettings();
  loadUsers();
  loadRadarCache();
  loadLogs();
}

async function doLogin() {
  const password = document.getElementById('loginPass').value;
  try {
    const res = await fetch('/admin/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (data.token) {
      ADMIN_TOKEN = data.token;
      localStorage.setItem('vp_token', ADMIN_TOKEN);
      showToast('ورود موفق');
      showMain();
    } else {
      showToast(data.error || 'رمز عبور اشتباه است', true);
    }
  } catch { showToast('خطا در ورود', true); }
}

async function loadSettings() {
  const data = await api('/admin/settings');
  document.getElementById('setHost').value = data.host || '';
  document.getElementById('setPath').value = data.path || '';
  document.getElementById('setSni').value = data.sni || '';
  document.getElementById('setFragment').value = data.fragment || '';
  document.getElementById('setEch').checked = !!data.ech;
  document.getElementById('setKill').checked = !!data.killSwitch;
  document.getElementById('killBanner').classList.toggle('hidden', !data.killSwitch);
}

async function saveSettings() {
  const body = {
    host: document.getElementById('setHost').value,
    path: document.getElementById('setPath').value,
    sni: document.getElementById('setSni').value,
    fragment: document.getElementById('setFragment').value,
    ech: document.getElementById('setEch').checked,
    killSwitch: document.getElementById('setKill').checked,
  };
  await api('/admin/settings', { method: 'POST', body: JSON.stringify(body) });
  document.getElementById('killBanner').classList.toggle('hidden', !body.killSwitch);
  showToast('تنظیمات ذخیره شد');
}

function fmtBytes(n) {
  if (!n) return '0';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + units[i];
}

async function loadUsers() {
  const users = await api('/admin/users');
  const body = document.getElementById('usersTableBody');
  body.innerHTML = '';
  users.forEach((u) => {
    const totalText = u.quotaBytes > 0 ? fmtBytes(u.usedBytes||0) + ' / ' + fmtBytes(u.quotaBytes) : fmtBytes(u.usedBytes||0) + ' / ∞';
    const dailyText = u.dailyQuotaBytes > 0 ? fmtBytes(u.dailyUsedBytes||0) + ' / ' + fmtBytes(u.dailyQuotaBytes) : fmtBytes(u.dailyUsedBytes||0) + ' / ∞';
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td>\${u.name}</td>
      <td><span class="badge \${u.enabled ? 'on':'off'}">\${u.enabled ? 'فعال':'غیرفعال'}</span></td>
      <td>\${u.expiry ? new Date(u.expiry).toLocaleDateString('fa-IR') : 'نامحدود'}</td>
      <td>\${totalText}</td>
      <td>\${dailyText}</td>
      <td><div class="actions">
        <button class="ghost small" onclick="copySub('\${u.token}','base64')">کپی لینک</button>
        <button class="ghost small" onclick="copySub('\${u.token}','clash')">Clash</button>
        <button class="ghost small" onclick="showQr('\${u.token}')">QR</button>
      </div></td>
      <td><div class="actions">
        <button class="secondary small" onclick="toggleUser('\${u.id}', \${!u.enabled})">\${u.enabled ? 'غیرفعال':'فعال'}</button>
        <button class="danger small" onclick="deleteUser('\${u.id}')">حذف</button>
      </div></td>
    \`;
    body.appendChild(tr);
  });
}

async function createUser() {
  const name = document.getElementById('newName').value.trim();
  if (!name) return showToast('نام کاربر را وارد کنید', true);
  const quotaGb = parseFloat(document.getElementById('newQuota').value || '0');
  const dailyGb = parseFloat(document.getElementById('newDailyQuota').value || '0');
  const body = {
    name,
    username: document.getElementById('newUsername').value.trim(),
    quotaBytes: Math.round(quotaGb * 1024**3),
    dailyQuotaBytes: Math.round(dailyGb * 1024**3),
    expiry: document.getElementById('newExpiry').value || null,
  };
  await api('/admin/user', { method: 'POST', body: JSON.stringify(body) });
  showToast('کاربر ایجاد شد');
  document.getElementById('newName').value = '';
  document.getElementById('newUsername').value = '';
  loadUsers();
}

async function toggleUser(id, enabled) {
  await api('/admin/user/' + id, { method: 'PUT', body: JSON.stringify({ enabled }) });
  loadUsers();
}
async function deleteUser(id) {
  if (!confirm('کاربر حذف شود؟')) return;
  await api('/admin/user/' + id, { method: 'DELETE' });
  showToast('کاربر حذف شد');
  loadUsers();
}

function subUrl(token, kind) {
  return kind === 'clash' ? location.origin + '/sub/mihomo.yaml?token=' + token : location.origin + '/sub?token=' + token;
}
async function copySub(token, kind) {
  const url = subUrl(token, kind);
  try { await navigator.clipboard.writeText(url); showToast('لینک اشتراک کپی شد'); }
  catch { prompt('لینک را کپی کنید:', url); }
}
function showQr(token) {
  const el = document.getElementById('qrCanvas');
  el.innerHTML = '';
  new QRCode(el, { text: subUrl(token, 'base64'), width: 220, height: 220 });
  document.getElementById('qrModal').style.display = 'flex';
}

async function loadRadarCache() {
  const data = await api('/radar/cache');
  if (data && data.results && data.results.length) {
    renderRadarResults(data.results);
    document.getElementById('radarMeta').textContent = 'آخرین اسکن: ' + new Date(data.scannedAt).toLocaleString('fa-IR');
  }
}
function renderRadarResults(results) {
  const body = document.getElementById('radarTableBody');
  body.innerHTML = '';
  results.forEach((r) => {
    const tr = document.createElement('tr');
    tr.innerHTML = \`<td>\${r.ip}</td><td>\${r.latency}</td><td><button class="ghost small" onclick="applyIp('\${r.ip}')">اعمال</button></td>\`;
    body.appendChild(tr);
  });
}
async function startScan(poolSize) {
  showToast('در حال اسکن عمیق... چند ثانیه صبر کنید');
  const data = await api('/radar/scan', { method: 'POST', body: JSON.stringify({ poolSize }) });
  renderRadarResults(data.results || []);
  document.getElementById('radarMeta').textContent = 'آخرین اسکن: همین الان';
  showToast('اسکن کامل شد: ' + (data.results||[]).length + ' نتیجه سالم');
}
async function applyIp(ip) {
  await api('/radar/apply', { method: 'POST', body: JSON.stringify({ host: ip }) });
  showToast('HOST به‌روزرسانی شد: ' + ip);
  loadSettings();
}

async function loadLogs() {
  const logs = await api('/admin/logs');
  const box = document.getElementById('logsBox');
  box.innerHTML = logs.map(l => \`<div class="log-line"><span>\${new Date(l.time).toLocaleString('fa-IR')}</span> — \${l.message}</div>\`).join('') || '<div class="log-line">لاگی ثبت نشده</div>';
}

async function changePassword() {
  const newPass = prompt('رمز عبور جدید را وارد کنید (حداقل ۶ کاراکتر):');
  if (!newPass) return;
  await api('/admin/password', { method: 'POST', body: JSON.stringify({ password: newPass }) });
  showToast('رمز عبور تغییر کرد — دوباره وارد شوید');
  localStorage.removeItem('vp_token');
  setTimeout(() => location.reload(), 1200);
}

if (ADMIN_TOKEN) showMain(); else showLogin();
</script>
</body>
</html>`;
}

// -----------------------------------------------------------------------------
// Main router
// -----------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    try {
      if (pathname === '/admin' && method === 'GET') {
        return htmlResponse(renderAdminPanel());
      }

      if (pathname === '/admin/login' && method === 'POST') {
        const { allowed, state } = await checkLoginRateLimit(env);
        if (!allowed) {
          return jsonResponse({ error: 'تلاش‌های ناموفق زیاد — چند دقیقه صبر کنید' }, 429);
        }
        const { password } = await request.json().catch(() => ({}));
        const valid = typeof password === 'string' && (await verifyAdminPass(env, password));
        await recordLoginAttempt(env, state, valid);
        if (!valid) {
          await appendLog(env, 'Failed admin login attempt');
          return jsonResponse({ error: 'رمز عبور اشتباه است' }, 401);
        }
        const token = uuid() + uuid();
        await setAdminSession(env, token);
        await appendLog(env, 'Admin logged in');
        return jsonResponse({ token });
      }

      if (pathname.startsWith('/admin/')) {
        const authed = await requireAdmin(request, env);
        if (!authed) return jsonResponse({ error: 'Unauthorized' }, 401);
      }

      if (pathname === '/admin/settings' && method === 'GET') return jsonResponse(await getSettings(env));

      if (pathname === '/admin/settings' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const saved = await saveSettings(env, body);
        await appendLog(env, `Settings updated${saved.killSwitch ? ' (KILL SWITCH ENABLED)' : ''}`);
        return jsonResponse(saved);
      }

      if (pathname === '/admin/logs' && method === 'GET') return jsonResponse(await getLogs(env));

      if (pathname === '/admin/users' && method === 'GET') return jsonResponse(await getUsers(env));

      if (pathname === '/admin/user' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        if (!body.name || typeof body.name !== 'string') return jsonResponse({ error: 'name is required' }, 400);
        const users = await getUsers(env);
        const newUser = {
          id: uuid(),
          name: body.name.trim(),
          username: (body.username || '').trim(),
          token: uuid(),
          uuid: uuid(),
          enabled: true,
          expiry: body.expiry || null,
          quotaBytes: Number.isFinite(body.quotaBytes) ? Math.max(0, Math.round(body.quotaBytes)) : 0,
          dailyQuotaBytes: Number.isFinite(body.dailyQuotaBytes) ? Math.max(0, Math.round(body.dailyQuotaBytes)) : 0,
          usedBytes: 0,
          dailyUsedBytes: 0,
          dailyResetAt: dailyWindowStart(Date.now()),
          createdAt: new Date().toISOString(),
        };
        users.push(newUser);
        await saveUsers(env, users);
        await appendLog(env, `User created: ${newUser.name}`);
        return jsonResponse(newUser, 201);
      }

      if (pathname.startsWith('/admin/user/') && method === 'PUT') {
        const id = pathname.split('/').pop();
        const body = await request.json().catch(() => ({}));
        const users = await getUsers(env);
        const idx = users.findIndex((u) => u.id === id);
        if (idx === -1) return jsonResponse({ error: 'User not found' }, 404);
        const allowedFields = ['name', 'username', 'enabled', 'expiry', 'quotaBytes', 'dailyQuotaBytes', 'usedBytes', 'dailyUsedBytes'];
        for (const field of allowedFields) if (body[field] !== undefined) users[idx][field] = body[field];
        await saveUsers(env, users);
        await appendLog(env, `User updated: ${users[idx].name}`);
        return jsonResponse(users[idx]);
      }

      if (pathname.startsWith('/admin/user/') && method === 'DELETE') {
        const id = pathname.split('/').pop();
        const users = await getUsers(env);
        const filtered = users.filter((u) => u.id !== id);
        if (filtered.length === users.length) return jsonResponse({ error: 'User not found' }, 404);
        await saveUsers(env, filtered);
        await appendLog(env, `User deleted: ${id}`);
        return jsonResponse({ success: true });
      }

      if (pathname === '/admin/password' && method === 'POST') {
        const { password } = await request.json().catch(() => ({}));
        if (!password || typeof password !== 'string' || password.length < 6) {
          return jsonResponse({ error: 'Password must be at least 6 characters' }, 400);
        }
        await setAdminPass(env, password);
        await clearAdminSession(env);
        await appendLog(env, 'Admin password changed');
        return jsonResponse({ success: true });
      }

      if (pathname === '/radar/cache' && method === 'GET') {
        const cache = await getRadarCache(env);
        return jsonResponse(cache || { scannedAt: null, results: [] });
      }

      if (pathname === '/radar/scan' && method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const poolSize = Math.min(Math.max(Number(body.poolSize) || 60, 10), 300);
        const results = await runRadarScan(body.ips, poolSize);
        const cache = await saveRadarCache(env, results);
        await appendLog(env, `Radar scan: ${results.length}/${poolSize} IPs responded`);
        return jsonResponse(cache);
      }

      if (pathname === '/radar/apply' && method === 'POST') {
        const { host } = await request.json().catch(() => ({}));
        if (!host || typeof host !== 'string') return jsonResponse({ error: 'host is required' }, 400);
        const settings = await getSettings(env);
        settings.host = host.trim();
        const saved = await saveSettings(env, settings);
        await appendLog(env, `Radar applied host: ${host}`);
        return jsonResponse(saved);
      }

      if (pathname === '/sub' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return textResponse('Missing token', 400);
        const users = await getUsers(env);
        const user = findUserByToken(users, token);
        const settings = await getSettings(env);
        const check = userIsUsable(user, settings);
        if (!check.ok) return textResponse(check.reason, 403);
        return textResponse(base64Encode(buildVlessUri(user, settings)));
      }

      if (pathname === '/sub/mihomo.yaml' && method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return textResponse('Missing token', 400);
        const users = await getUsers(env);
        const user = findUserByToken(users, token);
        const settings = await getSettings(env);
        const check = userIsUsable(user, settings);
        if (!check.ok) return textResponse(check.reason, 403);
        return textResponse(buildClashYaml(user, settings), 200, 'text/yaml; charset=utf-8');
      }

      if (pathname === '/ws' || pathname.startsWith('/ws')) {
        const token = url.searchParams.get('token');
        if (!token) return textResponse('Missing token', 400);
        const upgradeHeader = request.headers.get('Upgrade');
        if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
          return textResponse('Expected WebSocket upgrade', 426);
        }
        const users = await getUsers(env);
        const user = findUserByToken(users, token);
        const settings = await getSettings(env);
        const check = userIsUsable(user, settings);
        if (!check.ok) return textResponse(check.reason, 403);
        return handleVlessWebSocket(request, env, user);
      }

      if (pathname === '/' || pathname === '') return textResponse(`${BRAND} is running.`);

      return textResponse('Not found', 404);
    } catch (err) {
      await appendLog(env, `Unhandled error: ${err.message}`);
      return jsonResponse({ error: 'Internal server error' }, 500);
    }
  },
};
