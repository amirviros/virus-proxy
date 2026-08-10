// ============================================================
//  Zephyr Proxy — Cloudflare Worker
//  VLESS-over-WebSocket relay + admin panel + real ping test
//  Original implementation — not derived from any third-party
//  "protected release" source file.
// ============================================================

// ---------- CONFIG ----------
// Fill these in with YOUR real backend (Xray/V2Ray) details.
const DEFAULT_UUID = "00000000-0000-0000-0000-000000000000"; // replace with your client UUID
const PROXY_IP = "";            // optional: fixed outbound IP/domain for relay, leave blank to use client-provided host
const BRAND_NAME = "زفیر";
const BRAND_NAME_EN = "Zephyr";

// ---------- ENTRY POINT ----------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");

    // WebSocket upgrade => VLESS relay
    if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
      return handleVlessWebSocket(request, env);
    }

    // API routes
    if (url.pathname === "/api/ping") {
      return handlePingTest(url, env);
    }
    if (url.pathname === "/api/configs" && request.method === "GET") {
      return handleListConfigs(env);
    }
    if (url.pathname === "/api/configs" && request.method === "POST") {
      return handleCreateConfig(request, env);
    }
    if (url.pathname === "/api/configs" && request.method === "DELETE") {
      return handleDeleteConfig(url, env);
    }
    if (url.pathname === "/sub") {
      return handleSubscription(url, env);
    }

    // Admin panel (default page)
    return new Response(renderAdminPage(), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};

// ---------- REAL PING TEST (actual TCP connect, no faking) ----------
async function handlePingTest(url, env) {
  const host = url.searchParams.get("host");
  const port = parseInt(url.searchParams.get("port") || "443", 10);

  if (!host) {
    return json({ ok: false, error: "host is required" }, 400);
  }

  const start = Date.now();
  try {
    // Uses Cloudflare's raw TCP socket API to actually test reachability.
    const { connect } = await import("cloudflare:sockets");
    const socket = connect({ hostname: host, port });
    await socket.opened; // resolves once TCP handshake succeeds
    const latency = Date.now() - start;
    await socket.close();
    return json({ ok: true, host, port, latency_ms: latency });
  } catch (err) {
    // Genuine failure — reported as-is, never faked as positive.
    const latency = Date.now() - start;
    return json({
      ok: false,
      host,
      port,
      latency_ms: latency,
      error: "unreachable: " + (err?.message || String(err)),
    });
  }
}

// ---------- CONFIG STORAGE (uses YOUR KV namespace) ----------
// Bind a KV namespace called ZEPHYR_KV to this worker from your own
// Cloudflare dashboard (Workers & Pages -> KV -> Create namespace),
// then add the binding in wrangler.toml or the dashboard UI:
//
//   [[kv_namespaces]]
//   binding = "ZEPHYR_KV"
//   id = "YOUR_OWN_NAMESPACE_ID"
//
async function handleListConfigs(env) {
  if (!env.ZEPHYR_KV) {
    return json({ ok: false, error: "ZEPHYR_KV binding not configured" }, 500);
  }
  const list = await env.ZEPHYR_KV.list({ prefix: "config:" });
  const items = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.ZEPHYR_KV.get(k.name, "json");
      return { key: k.name, ...val };
    })
  );
  return json({ ok: true, configs: items });
}

async function handleCreateConfig(request, env) {
  if (!env.ZEPHYR_KV) {
    return json({ ok: false, error: "ZEPHYR_KV binding not configured" }, 500);
  }
  const body = await request.json().catch(() => null);
  if (!body || !body.host || !body.port) {
    return json({ ok: false, error: "host and port are required" }, 400);
  }
  const id = crypto.randomUUID();
  const entry = {
    id,
    name: body.name || "config-" + id.slice(0, 8),
    host: body.host,
    port: parseInt(body.port, 10),
    uuid: body.uuid || DEFAULT_UUID,
    path: body.path || "/ws",
    createdAt: new Date().toISOString(),
  };
  await env.ZEPHYR_KV.put("config:" + id, JSON.stringify(entry));
  return json({ ok: true, config: entry });
}

async function handleDeleteConfig(url, env) {
  if (!env.ZEPHYR_KV) {
    return json({ ok: false, error: "ZEPHYR_KV binding not configured" }, 500);
  }
  const id = url.searchParams.get("id");
  if (!id) return json({ ok: false, error: "id is required" }, 400);
  await env.ZEPHYR_KV.delete("config:" + id);
  return json({ ok: true });
}

// ---------- SUBSCRIPTION LINK GENERATION ----------
function handleSubscription(url, env) {
  const host = url.searchParams.get("host") || url.hostname;
  const port = url.searchParams.get("port") || "443";
  const uuid = url.searchParams.get("uuid") || DEFAULT_UUID;
  const path = url.searchParams.get("path") || "/ws";
  const name = encodeURIComponent(url.searchParams.get("name") || BRAND_NAME_EN);

  const vlessLink =
    `vless://${uuid}@${host}:${port}` +
    `?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=${encodeURIComponent(path)}` +
    `#${name}`;

  return new Response(btoa(vlessLink), {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// ---------- VLESS OVER WEBSOCKET RELAY ----------
// Minimal VLESS protocol parser + raw TCP relay via cloudflare:sockets.
// This talks to YOUR backend server — it does not depend on any
// third-party service.
async function handleVlessWebSocket(request, env) {
  const { connect } = await import("cloudflare:sockets");
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  let remoteSocket = null;
  let udpWrite = null;

  server.addEventListener("message", async (event) => {
    try {
      if (!remoteSocket) {
        // First message contains the VLESS header
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

        // Pipe remote -> client
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
    // connection closed
  } finally {
    server.close();
  }
}

// Parses the VLESS protocol header. Returns destination host/port and
// the remaining payload bytes. See VLESS protocol spec (public, open).
function parseVlessHeader(buffer, expectedUuid) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // byte 0: version (ignored)
  // bytes 1-16: UUID
  const uuidBytes = bytes.slice(1, 17);
  const uuid = bytesToUuid(uuidBytes);
  const uuidValid = uuid === expectedUuid;

  let offset = 17;
  const optLength = bytes[offset];
  offset += 1 + optLength; // skip addons

  const command = bytes[offset]; // 1 = TCP, 2 = UDP
  offset += 1;

  const port = view.getUint16(offset);
  offset += 2;

  const addrType = bytes[offset];
  offset += 1;

  let hostname = "";
  if (addrType === 1) {
    // IPv4
    hostname = bytes.slice(offset, offset + 4).join(".");
    offset += 4;
  } else if (addrType === 2) {
    // domain
    const len = bytes[offset];
    offset += 1;
    hostname = new TextDecoder().decode(bytes.slice(offset, offset + len));
    offset += len;
  } else if (addrType === 3) {
    // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(offset + i * 2).toString(16));
    }
    hostname = parts.join(":");
    offset += 16;
  }

  const rawClientData = buffer.slice(offset);
  return { hostname, port, rawClientData, uuidValid, command };
}

function bytesToUuid(bytes) {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0"));
  return (
    hex.slice(0, 4).join("") +
    "-" +
    hex.slice(4, 6).join("") +
    "-" +
    hex.slice(6, 8).join("") +
    "-" +
    hex.slice(8, 10).join("") +
    "-" +
    hex.slice(10, 16).join("")
  );
}

// ---------- HELPERS ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// ---------- ADMIN PANEL (cream theme, Zephyr brand) ----------
function renderAdminPage() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${BRAND_NAME} پروکسی</title>
<style>
  :root {
    --cream-bg: #f5f1e8;
    --cream-card: #fffdf7;
    --cream-border: #e6ddc6;
    --accent: #c9a86a;
    --accent-dark: #8a6d3b;
    --text: #3a3226;
    --success: #4a7c59;
    --error: #b34747;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Vazirmatn", -apple-system, Tahoma, sans-serif;
    background: var(--cream-bg);
    color: var(--text);
    padding: 24px;
  }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { color: var(--accent-dark); font-size: 24px; }
  .card {
    background: var(--cream-card);
    border: 1px solid var(--cream-border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.04);
  }
  label { display: block; margin-bottom: 6px; font-size: 13px; color: var(--accent-dark); }
  input {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--cream-border);
    border-radius: 8px;
    margin-bottom: 12px;
    background: #fff;
    font-family: inherit;
  }
  button {
    background: var(--accent);
    color: #fff;
    border: none;
    padding: 10px 18px;
    border-radius: 8px;
    cursor: pointer;
    font-family: inherit;
    font-size: 14px;
  }
  button:hover { background: var(--accent-dark); }
  .config-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid var(--cream-border);
  }
  .ping-badge { font-size: 12px; padding: 3px 8px; border-radius: 6px; }
  .ping-ok { background: #e3efe4; color: var(--success); }
  .ping-fail { background: #f3e3e3; color: var(--error); }
</style>
</head>
<body>
<div class="container">
  <h1>پنل ${BRAND_NAME}</h1>

  <div class="card">
    <h3>افزودن سرور جدید</h3>
    <label>نام</label>
    <input id="f-name" placeholder="مثلاً سرور آلمان">
    <label>دامنه بک‌اند</label>
    <input id="f-host" placeholder="example.com">
    <label>پورت</label>
    <input id="f-port" value="443">
    <label>UUID</label>
    <input id="f-uuid" placeholder="uuid کلاینت">
    <button onclick="addConfig()">افزودن</button>
  </div>

  <div class="card">
    <h3>سرورها</h3>
    <div id="config-list">در حال بارگذاری...</div>
  </div>
</div>

<script>
async function loadConfigs() {
  const res = await fetch('/api/configs');
  const data = await res.json();
  const list = document.getElementById('config-list');
  if (!data.ok) { list.textContent = data.error; return; }
  if (!data.configs.length) { list.textContent = 'هنوز سروری اضافه نشده.'; return; }
  list.innerHTML = '';
  for (const c of data.configs) {
    const row = document.createElement('div');
    row.className = 'config-row';
    row.innerHTML = \`
      <span>\${c.name} — \${c.host}:\${c.port}</span>
      <span id="ping-\${c.id}" class="ping-badge">در حال تست...</span>
    \`;
    list.appendChild(row);
    testPing(c.id, c.host, c.port);
  }
}

async function testPing(id, host, port) {
  const badge = document.getElementById('ping-' + id);
  try {
    const res = await fetch(\`/api/ping?host=\${host}&port=\${port}\`);
    const data = await res.json();
    if (data.ok) {
      badge.textContent = data.latency_ms + ' ms';
      badge.className = 'ping-badge ping-ok';
    } else {
      badge.textContent = 'خطا';
      badge.className = 'ping-badge ping-fail';
    }
  } catch (e) {
    badge.textContent = 'خطا';
    badge.className = 'ping-badge ping-fail';
  }
}

async function addConfig() {
  const body = {
    name: document.getElementById('f-name').value,
    host: document.getElementById('f-host').value,
    port: document.getElementById('f-port').value,
    uuid: document.getElementById('f-uuid').value,
  };
  const res = await fetch('/api/configs', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.ok) { loadConfigs(); } else { alert(data.error); }
}

loadConfigs();
</script>
</body>
</html>`;
}
