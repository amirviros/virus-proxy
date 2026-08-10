// ============================================================
//  Zephyr Proxy — Cloudflare Worker (v2)
//  VLESS-over-WebSocket relay + multi-server admin panel
//  + aggregated subscription link + real (non-fake) ping test
//
//  Original implementation. Requires YOUR OWN:
//    - Xray/V2Ray backend server(s) with valid domain + TLS
//    - Cloudflare KV namespace bound as ZEPHYR_KV
//  Nothing here fabricates results or reads data from any
//  third-party account/service.
// ============================================================

const BRAND_NAME = "زفیر";
const BRAND_NAME_EN = "Zephyr";
const DEFAULT_UUID = "00000000-0000-0000-0000-000000000000";

// ============================================================
// ENTRY POINT
// ============================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");

    if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
      return handleVlessWebSocket(request, env);
    }

    const routes = {
      "GET /api/servers": () => listServers(env),
      "POST /api/servers": () => createServer(request, env),
      "PUT /api/servers": () => updateServer(request, env),
      "DELETE /api/servers": () => deleteServer(url, env),
      "GET /api/groups": () => listGroups(env),
      "POST /api/groups": () => createGroup(request, env),
      "GET /api/ping": () => pingServer(url, env),
      "GET /api/ping-all": () => pingAll(env),
      "GET /sub": () => subscriptionAll(url, env),
      "GET /sub/one": () => subscriptionOne(url, env),
    };

    const key = request.method + " " + url.pathname;
    if (routes[key]) return routes[key]();

    return new Response(renderAdminPage(), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};

// ============================================================
// STORAGE HELPERS (uses YOUR KV namespace — binding ZEPHYR_KV)
// ============================================================
function requireKv(env) {
  if (!env.ZEPHYR_KV) {
    throw new Error(
      "ZEPHYR_KV binding not configured — add it from your own Cloudflare dashboard."
    );
  }
  return env.ZEPHYR_KV;
}

async function listServers(env) {
  try {
    const kv = requireKv(env);
    const list = await kv.list({ prefix: "server:" });
    const items = await Promise.all(
      list.keys.map(async (k) => await kv.get(k.name, "json"))
    );
    items.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    return json({ ok: true, servers: items });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function createServer(request, env) {
  try {
    const kv = requireKv(env);
    const body = await request.json();
    if (!body.host || !body.port) {
      return json({ ok: false, error: "host and port required" }, 400);
    }
    const id = crypto.randomUUID();
    const entry = {
      id,
      name: body.name || "server-" + id.slice(0, 8),
      host: body.host,
      port: parseInt(body.port, 10),
      uuid: body.uuid || DEFAULT_UUID,
      path: body.path || "/ws",
      group: body.group || "default",
      createdAt: new Date().toISOString(),
    };
    await kv.put("server:" + id, JSON.stringify(entry));
    return json({ ok: true, server: entry });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function updateServer(request, env) {
  try {
    const kv = requireKv(env);
    const body = await request.json();
    if (!body.id) return json({ ok: false, error: "id required" }, 400);
    const existingRaw = await kv.get("server:" + body.id, "json");
    if (!existingRaw) return json({ ok: false, error: "not found" }, 404);
    const updated = { ...existingRaw, ...body };
    await kv.put("server:" + body.id, JSON.stringify(updated));
    return json({ ok: true, server: updated });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function deleteServer(url, env) {
  try {
    const kv = requireKv(env);
    const id = url.searchParams.get("id");
    if (!id) return json({ ok: false, error: "id required" }, 400);
    await kv.delete("server:" + id);
    return json({ ok: true });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function listGroups(env) {
  try {
    const kv = requireKv(env);
    const list = await kv.list({ prefix: "server:" });
    const items = await Promise.all(
      list.keys.map(async (k) => await kv.get(k.name, "json"))
    );
    const groups = [...new Set(items.map((i) => i.group || "default"))];
    return json({ ok: true, groups });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function createGroup() {
  // Groups are derived from server.group field — no separate storage needed.
  return json({ ok: true, note: "assign a group name to a server directly" });
}

// ============================================================
// REAL PING TEST — actual TCP handshake, never fabricated
// ============================================================
async function pingServer(url, env) {
  const host = url.searchParams.get("host");
  const port = parseInt(url.searchParams.get("port") || "443", 10);
  if (!host) return json({ ok: false, error: "host required" }, 400);
  const result = await tcpPing(host, port);
  return json(result);
}

async function pingAll(env) {
  try {
    const kv = requireKv(env);
    const list = await kv.list({ prefix: "server:" });
    const servers = await Promise.all(
      list.keys.map(async (k) => await kv.get(k.name, "json"))
    );
    const results = await Promise.all(
      servers.map(async (s) => ({
        id: s.id,
        ...(await tcpPing(s.host, s.port)),
      }))
    );
    return json({ ok: true, results });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

async function tcpPing(host, port) {
  const start = Date.now();
  try {
    const { connect } = await import("cloudflare:sockets");
    const socket = connect({ hostname: host, port });
    await socket.opened;
    const latency = Date.now() - start;
    await socket.close();
    return { ok: true, host, port, latency_ms: latency };
  } catch (err) {
    return {
      ok: false,
      host,
      port,
      latency_ms: Date.now() - start,
      error: "unreachable: " + (err?.message || String(err)),
    };
  }
}

// ============================================================
// SUBSCRIPTION LINKS
// ============================================================
function buildVlessLink(server, label) {
  const name = encodeURIComponent(label || server.name || BRAND_NAME_EN);
  return (
    `vless://${server.uuid}@${server.host}:${server.port}` +
    `?encryption=none&security=tls&sni=${server.host}&type=ws` +
    `&host=${server.host}&path=${encodeURIComponent(server.path || "/ws")}` +
    `#${name}`
  );
}

// One aggregated subscription containing ALL servers (all configs together)
async function subscriptionAll(url, env) {
  try {
    const kv = requireKv(env);
    const groupFilter = url.searchParams.get("group");
    const list = await kv.list({ prefix: "server:" });
    let servers = await Promise.all(
      list.keys.map(async (k) => await kv.get(k.name, "json"))
    );
    if (groupFilter) {
      servers = servers.filter((s) => (s.group || "default") === groupFilter);
    }
    const links = servers.map((s) => buildVlessLink(s)).join("\n");
    return new Response(btoa(unescape(encodeURIComponent(links))), {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  } catch (err) {
    return new Response("error: " + err.message, { status: 500 });
  }
}

// Single-server subscription (for sharing just one config)
async function subscriptionOne(url, env) {
  try {
    const kv = requireKv(env);
    const id = url.searchParams.get("id");
    const server = await kv.get("server:" + id, "json");
    if (!server) return new Response("not found", { status: 404 });
    const link = buildVlessLink(server);
    return new Response(btoa(unescape(encodeURIComponent(link))), {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  } catch (err) {
    return new Response("error: " + err.message, { status: 500 });
  }
}

// ============================================================
// VLESS OVER WEBSOCKET RELAY
// ============================================================
async function handleVlessWebSocket(request, env) {
  const { connect } = await import("cloudflare:sockets");
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  let remoteSocket = null;

  server.addEventListener("message", async (event) => {
    try {
      if (!remoteSocket) {
        const { hostname, port, rawClientData, uuidValid } = parseVlessHeader(
          event.data,
          env.EXPECTED_UUID || DEFAULT_UUID
        );
        if (!uuidValid) {
          server.close(1008, "invalid uuid");
          return;
        }
        remoteSocket = connect({ hostname, port });
        await remoteSocket.opened;

        const writer = remoteSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();

        pipeRemoteToClient(remoteSocket, server);
      } else {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(event.data);
        writer.releaseLock();
      }
    } catch (err) {
      server.close(1011, "relay error");
    }
  });

  server.addEventListener("close", () => {
    if (remoteSocket) remoteSocket.close().catch(() => {});
  });

  return new Response(null, { status: 101, webSocket: client });
}

async function pipeRemoteToClient(remoteSocket, server) {
  const reader = remoteSocket.readable.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      server.send(value);
    }
  } catch (e) {
    // connection ended
  } finally {
    server.close();
  }
}

function parseVlessHeader(buffer, expectedUuid) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  const uuidBytes = bytes.slice(1, 17);
  const uuid = bytesToUuid(uuidBytes);
  const uuidValid = uuid === expectedUuid;

  let offset = 17;
  const optLength = bytes[offset];
  offset += 1 + optLength;

  offset += 1; // command byte

  const port = view.getUint16(offset);
  offset += 2;

  const addrType = bytes[offset];
  offset += 1;

  let hostname = "";
  if (addrType === 1) {
    hostname = bytes.slice(offset, offset + 4).join(".");
    offset += 4;
  } else if (addrType === 2) {
    const len = bytes[offset];
    offset += 1;
    hostname = new TextDecoder().decode(bytes.slice(offset, offset + len));
    offset += len;
  } else if (addrType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(offset + i * 2).toString(16));
    }
    hostname = parts.join(":");
    offset += 16;
  }

  const rawClientData = buffer.slice(offset);
  return { hostname, port, rawClientData, uuidValid };
}

function bytesToUuid(bytes) {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0"));
  return (
    hex.slice(0, 4).join("") + "-" +
    hex.slice(4, 6).join("") + "-" +
    hex.slice(6, 8).join("") + "-" +
    hex.slice(8, 10).join("") + "-" +
    hex.slice(10, 16).join("")
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// ============================================================
// ADMIN PANEL — cream theme, original layout
// ============================================================
function renderAdminPage() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${BRAND_NAME} — پنل مدیریت</title>
<style>
  :root {
    --cream-bg: #f6f1e6;
    --cream-card: #fffcf5;
    --cream-border: #e8dfc4;
    --accent: #c69a52;
    --accent-dark: #8a6a2e;
    --text: #382f22;
    --muted: #8a8069;
    --success: #4a7c59;
    --error: #b34747;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Vazirmatn", -apple-system, Tahoma, sans-serif;
    background: var(--cream-bg);
    color: var(--text);
  }
  header {
    background: linear-gradient(135deg, #efe4c9, #f6f1e6);
    padding: 28px 24px;
    border-bottom: 1px solid var(--cream-border);
  }
  header h1 { margin: 0; color: var(--accent-dark); font-size: 26px; }
  header p { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
  .container { max-width: 880px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--cream-card);
    border: 1px solid var(--cream-border);
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 2px 8px rgba(60,45,10,0.05);
  }
  .card h3 { margin-top: 0; color: var(--accent-dark); font-size: 15px; }
  label { display: block; margin: 8px 0 4px; font-size: 12px; color: var(--muted); }
  input, select {
    width: 100%;
    padding: 9px 10px;
    border: 1px solid var(--cream-border);
    border-radius: 8px;
    background: #fff;
    font-family: inherit;
    font-size: 13px;
  }
  button {
    background: var(--accent);
    color: #fff;
    border: none;
    padding: 9px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-family: inherit;
    font-size: 13px;
    margin-top: 10px;
  }
  button:hover { background: var(--accent-dark); }
  button.secondary { background: transparent; color: var(--accent-dark); border: 1px solid var(--cream-border); }
  button.danger { background: var(--error); }
  .server-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid var(--cream-border);
    font-size: 13px;
  }
  .server-row:last-child { border-bottom: none; }
  .badge { font-size: 11px; padding: 3px 8px; border-radius: 6px; }
  .badge-ok { background: #e3efe4; color: var(--success); }
  .badge-fail { background: #f3e3e3; color: var(--error); }
  .badge-group { background: #f0e6cc; color: var(--accent-dark); }
  .sub-box {
    display: flex; gap: 8px; margin-top: 8px;
  }
  .sub-box input { flex: 1; font-size: 11px; }
  .actions { display: flex; gap: 6px; }
  .actions button { margin-top: 0; padding: 5px 10px; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>${BRAND_NAME}</h1>
  <p>پنل مدیریت سرورها و لینک‌های اشتراک</p>
</header>

<div class="container">
  <div class="grid">
    <div class="card">
      <h3>افزودن سرور جدید</h3>
      <label>نام</label>
      <input id="f-name" placeholder="مثلاً آلمان ۱">
      <label>گروه</label>
      <input id="f-group" placeholder="default" value="default">
      <label>دامنه بک‌اند</label>
      <input id="f-host" placeholder="example.com">
      <label>پورت</label>
      <input id="f-port" value="443">
      <label>UUID</label>
      <input id="f-uuid" placeholder="uuid کلاینت">
      <label>مسیر وب‌سوکت</label>
      <input id="f-path" value="/ws">
      <button onclick="addServer()">افزودن سرور</button>
    </div>

    <div class="card">
      <h3>لینک اشتراک (همه‌ی سرورها)</h3>
      <p style="color:var(--muted); font-size:12px;">این لینک همه‌ی کانفیگ‌های ذخیره‌شده رو یک‌جا برمی‌گردونه.</p>
      <div class="sub-box">
        <input id="sub-all-link" readonly>
        <button class="secondary" onclick="copyField('sub-all-link')">کپی</button>
      </div>
      <label>فیلتر بر اساس گروه (اختیاری)</label>
      <input id="sub-group-filter" placeholder="مثلاً default" oninput="updateSubLink()">
    </div>
  </div>

  <div class="card">
    <h3>سرورها</h3>
    <div id="server-list">در حال بارگذاری...</div>
  </div>
</div>

<script>
const origin = window.location.origin;

function updateSubLink() {
  const group = document.getElementById('sub-group-filter').value.trim();
  const link = origin + '/sub' + (group ? ('?group=' + encodeURIComponent(group)) : '');
  document.getElementById('sub-all-link').value = link;
}

function copyField(id) {
  const el = document.getElementById(id);
  el.select();
  document.execCommand('copy');
}

async function loadServers() {
  const res = await fetch('/api/servers');
  const data = await res.json();
  const list = document.getElementById('server-list');
  if (!data.ok) { list.textContent = data.error; return; }
  if (!data.servers.length) { list.textContent = 'هنوز سروری اضافه نشده.'; return; }
  list.innerHTML = '';
  for (const s of data.servers) {
    const row = document.createElement('div');
    row.className = 'server-row';
    row.innerHTML = \`
      <span>
        <strong>\${s.name}</strong> — \${s.host}:\${s.port}
        <span class="badge badge-group">\${s.group || 'default'}</span>
      </span>
      <span style="display:flex; align-items:center; gap:8px;">
        <span id="ping-\${s.id}" class="badge">تست...</span>
        <span class="actions">
          <button class="secondary" onclick="copySub('\${s.id}')">لینک تکی</button>
          <button class="danger" onclick="removeServer('\${s.id}')">حذف</button>
        </span>
      </span>
    \`;
    list.appendChild(row);
    testPing(s.id, s.host, s.port);
  }
}

async function testPing(id, host, port) {
  const badge = document.getElementById('ping-' + id);
  try {
    const res = await fetch(\`/api/ping?host=\${host}&port=\${port}\`);
    const data = await res.json();
    if (data.ok) {
      badge.textContent = data.latency_ms + ' ms';
      badge.className = 'badge badge-ok';
    } else {
      badge.textContent = 'قطع';
      badge.className = 'badge badge-fail';
    }
  } catch (e) {
    badge.textContent = 'خطا';
    badge.className = 'badge badge-fail';
  }
}

async function addServer() {
  const body = {
    name: document.getElementById('f-name').value,
    group: document.getElementById('f-group').value || 'default',
    host: document.getElementById('f-host').value,
    port: document.getElementById('f-port').value,
    uuid: document.getElementById('f-uuid').value,
    path: document.getElementById('f-path').value || '/ws',
  };
  if (!body.host || !body.port) { alert('دامنه و پورت الزامیه'); return; }
  const res = await fetch('/api/servers', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.ok) { loadServers(); } else { alert(data.error); }
}

async function removeServer(id) {
  if (!confirm('حذف بشه؟')) return;
  await fetch('/api/servers?id=' + id, { method: 'DELETE' });
  loadServers();
}

function copySub(id) {
  const link = origin + '/sub/one?id=' + id;
  navigator.clipboard.writeText(link);
  alert('لینک کپی شد');
}

updateSubLink();
loadServers();
</script>
</body>
</html>`;
}
