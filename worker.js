// ================================================================
//  Amir Nova Proxy  —  Cloudflare Worker
//  پروکسی VLESS-over-WebSocket با پنل مدیریت، اسکنر IP، Health-Check
//  و به‌روزرسانی خودکار HOST
//
//  نکته مهم (بخوانید!):
//  این کد ساختار پروتکل VLESS و WebSocket proxy را از الگوی متداول
//  و عمومیِ پروژه‌های "vless-worker" می‌گیرد (همان چیزی که در
//  Amir Virus هم وجود دارد) و بخش‌های مدیریتی/اسکن/آپدیت خودکار را
//  به آن اضافه می‌کند. قبل از استفاده‌ی واقعی حتماً تست کنید.
// ================================================================

import { connect } from 'cloudflare:sockets';

// ---------------------------------------------------------------
// ثابت‌ها و مقادیر پیش‌فرض
// ---------------------------------------------------------------
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// اگر در KV هنوز تنظیمات اولیه ست نشده باشد از این مقادیر استفاده می‌شود
const DEFAULT_CONFIG = {
	host: '',              // HOST فعلی که به‌صورت خودکار آپدیت می‌شود
	path: '/vless-ws',      // مسیر وب‌سوکت
	sni: '',                // در صورت خالی بودن از host استفاده می‌شود
	fragment: 'tlshello,1,fake', // پارامتر fragment برای کلاینت‌هایی که ساپورت می‌کنند
	ech: '',                // ECH config (اختیاری - خالی یعنی غیرفعال)
	killSwitch: false,      // اگر true باشد همه اتصالات رد می‌شوند
	candidateIPs: [
		// این‌ها فقط نمونه‌اند؛ حتماً از پنل، لیست IP تمیز/به‌روز خودتان را وارد کنید
		'104.16.0.0', '104.17.0.0', '104.18.0.0', '104.19.0.0', '104.20.0.0'
	],
	lastScanAt: 0,
	lastScanResults: [] // [{ip, latencyMs}]
};

// ---------------------------------------------------------------
// توابع کمکی عمومی
// ---------------------------------------------------------------

function uuidv4() {
	return crypto.randomUUID();
}

function nowISO() {
	return new Date().toISOString();
}

async function getConfig(env) {
	const raw = await env.NOVA_KV.get('config');
	if (!raw) {
		await env.NOVA_KV.put('config', JSON.stringify(DEFAULT_CONFIG));
		return { ...DEFAULT_CONFIG };
	}
	return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
}

async function saveConfig(env, cfg) {
	await env.NOVA_KV.put('config', JSON.stringify(cfg));
}

async function addLog(env, type, message) {
	const key = 'log:' + Date.now() + ':' + Math.random().toString(36).slice(2, 7);
	const entry = { type, message, time: nowISO() };
	await env.NOVA_KV.put(key, JSON.stringify(entry), { expirationTtl: 60 * 60 * 24 * 14 }); // ۱۴ روز نگهداری
}

async function getLogs(env, limit = 100) {
	const list = await env.NOVA_KV.list({ prefix: 'log:', limit: 1000 });
	const keys = list.keys.map(k => k.name).sort().reverse().slice(0, limit);
	const entries = await Promise.all(keys.map(k => env.NOVA_KV.get(k)));
	return entries.filter(Boolean).map(e => JSON.parse(e));
}

// کاربران در KV با پیشوند user: ذخیره می‌شوند
async function getUser(env, token) {
	const raw = await env.NOVA_KV.get('user:' + token);
	return raw ? JSON.parse(raw) : null;
}

async function saveUser(env, user) {
	await env.NOVA_KV.put('user:' + user.token, JSON.stringify(user));
}

async function listUsers(env) {
	const list = await env.NOVA_KV.list({ prefix: 'user:' });
	const users = await Promise.all(list.keys.map(k => env.NOVA_KV.get(k.name)));
	return users.filter(Boolean).map(u => JSON.parse(u));
}

async function deleteUser(env, token) {
	await env.NOVA_KV.delete('user:' + token);
}

// بررسی معتبر بودن کاربر: فعال بودن، منقضی نشدن، رد نشدن از سقف ترافیک
function isUserValid(user) {
	if (!user || !user.active) return false;
	if (user.expiresAt && Date.now() > user.expiresAt) return false;
	if (user.trafficLimitTotal > 0 && user.trafficUsedTotal >= user.trafficLimitTotal) return false;
	if (user.trafficLimitDaily > 0) {
		const today = new Date().toISOString().slice(0, 10);
		if (user.dailyDate === today && user.trafficUsedDaily >= user.trafficLimitDaily) return false;
	}
	return true;
}

function trackUsage(user, bytes) {
	const today = new Date().toISOString().slice(0, 10);
	if (user.dailyDate !== today) {
		user.dailyDate = today;
		user.trafficUsedDaily = 0;
	}
	user.trafficUsedTotal = (user.trafficUsedTotal || 0) + bytes;
	user.trafficUsedDaily = (user.trafficUsedDaily || 0) + bytes;
}

// ---------------------------------------------------------------
// احراز هویت پنل ادمین (کوکی ساده امضاشده)
// ---------------------------------------------------------------

async function sha256Hex(text) {
	const data = new TextEncoder().encode(text);
	const hash = await crypto.subtle.digest('SHA-256', data);
	return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function makeSessionToken(env) {
	const raw = env.ADMIN_PASS + ':' + Math.floor(Date.now() / (1000 * 60 * 60 * 12)); // هر ۱۲ ساعت عوض می‌شود
	return sha256Hex(raw);
}

async function isAuthed(request, env) {
	const cookie = request.headers.get('Cookie') || '';
	const match = cookie.match(/nova_session=([a-f0-9]+)/);
	if (!match) return false;
	const expected = await makeSessionToken(env);
	return match[1] === expected;
}

// ---------------------------------------------------------------
// منطق VLESS (پارس هدر + تونل TCP)
// این بخش همان ساختار استاندارد vless-over-websocket است.
// ---------------------------------------------------------------

function base64ToUint8(base64Str) {
	base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
	const decoded = atob(base64Str);
	const arr = new Uint8Array(decoded.length);
	for (let i = 0; i < decoded.length; i++) arr[i] = decoded.charCodeAt(i);
	return arr;
}

// پارس کردن هدر VLESS طبق مستندات پروتکل
function parseVlessHeader(buffer, validUUID) {
	const view = new DataView(buffer);
	const version = view.getUint8(0);
	const idBytes = new Uint8Array(buffer.slice(1, 17));
	const idStr = [...idBytes].map(b => b.toString(16).padStart(2, '0')).join('');
	const formattedId = `${idStr.slice(0,8)}-${idStr.slice(8,12)}-${idStr.slice(12,16)}-${idStr.slice(16,20)}-${idStr.slice(20)}`;
	if (formattedId !== validUUID) {
		return { hasError: true, message: 'UUID نامعتبر است' };
	}
	const optLength = view.getUint8(17);
	const cmdOffset = 18 + optLength;
	const command = view.getUint8(cmdOffset); // 1 = TCP, 2 = UDP
	const portOffset = cmdOffset + 1;
	const port = view.getUint16(portOffset);
	const addrTypeOffset = portOffset + 2;
	const addrType = view.getUint8(addrTypeOffset);
	let addrLength = 0, addrValueOffset = addrTypeOffset + 1, address = '';

	if (addrType === 1) { // IPv4
		addrLength = 4;
		address = new Uint8Array(buffer.slice(addrValueOffset, addrValueOffset + addrLength)).join('.');
	} else if (addrType === 2) { // Domain
		addrLength = view.getUint8(addrValueOffset);
		addrValueOffset += 1;
		address = new TextDecoder().decode(buffer.slice(addrValueOffset, addrValueOffset + addrLength));
	} else if (addrType === 3) { // IPv6
		addrLength = 16;
		const dv = new DataView(buffer.slice(addrValueOffset, addrValueOffset + addrLength));
		const parts = [];
		for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
		address = parts.join(':');
	} else {
		return { hasError: true, message: 'نوع آدرس نامعتبر است' };
	}

	return {
		hasError: false,
		addressType: addrType,
		addressRemote: address,
		portRemote: port,
		rawDataIndex: addrValueOffset + addrLength,
		vlessVersion: new Uint8Array([version]),
		isUDP: command === 2,
	};
}

// تبدیل ReadableStream وب‌سوکت به یک stream قابل استفاده
function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
	let readableStreamCancel = false;
	return new ReadableStream({
		start(controller) {
			webSocket.addEventListener('message', (event) => {
				if (readableStreamCancel) return;
				controller.enqueue(event.data);
			});
			webSocket.addEventListener('close', () => {
				if (!readableStreamCancel) controller.close();
			});
			webSocket.addEventListener('error', (err) => {
				controller.error(err);
			});
			// داده‌های early-data (0-RTT) که ممکن است در هدر base64 آمده باشند
			try {
				if (earlyDataHeader) {
					const earlyData = base64ToUint8(earlyDataHeader);
					controller.enqueue(earlyData.buffer);
				}
			} catch (e) { /* بی‌اهمیت اگر early data نبود */ }
		},
		cancel() {
			readableStreamCancel = true;
			safeCloseWebSocket(webSocket);
		}
	});
}

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (e) { /* نادیده گرفتن خطای بستن */ }
}

// هسته اصلی هندل کردن یک اتصال VLESS روی WebSocket
async function handleVlessWebSocket(request, env, user) {
	const [client, webSocket] = Object.values(new WebSocketPair());
	webSocket.accept();

	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

	let remoteSocket = null;
	let udpWrite = null;
	let isDNS = false;
	let totalBytes = 0;

	readableStream.pipeTo(new WritableStream({
		async write(chunk) {
			if (remoteSocket) {
				const writer = remoteSocket.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				totalBytes += chunk.byteLength;
				return;
			}

			const vlessHeader = parseVlessHeader(chunk, user.uuid);
			if (vlessHeader.hasError) {
				safeCloseWebSocket(webSocket);
				return;
			}

			const rawClientData = chunk.slice(vlessHeader.rawDataIndex);
			const vlessRespHeader = new Uint8Array([vlessHeader.vlessVersion[0], 0]);

			if (vlessHeader.isUDP) {
				// در این نسخه ساده، UDP فقط برای DNS پشتیبانی می‌شود (مانند اکثر پیاده‌سازی‌های vless-worker)
				if (vlessHeader.portRemote !== 53) {
					safeCloseWebSocket(webSocket);
					return;
				}
				isDNS = true;
			}

			if (isDNS) {
				// درخواست DNS را به سرویس DoH کلودفلر forward می‌کنیم
				const dnsResp = await fetch('https://1.1.1.1/dns-query', {
					method: 'POST',
					headers: { 'content-type': 'application/dns-message' },
					body: rawClientData,
				});
				const dnsRespBuf = await dnsResp.arrayBuffer();
				const sizeBuf = new Uint8Array([(dnsRespBuf.byteLength >> 8) & 0xff, dnsRespBuf.byteLength & 0xff]);
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					webSocket.send(await new Blob([vlessRespHeader, sizeBuf, dnsRespBuf]).arrayBuffer());
				}
				return;
			}

			// اتصال TCP واقعی به مقصد از طریق Cloudflare TCP Sockets API
			remoteSocket = connect({ hostname: vlessHeader.addressRemote, port: vlessHeader.portRemote });
			const writer = remoteSocket.writable.getWriter();
			await writer.write(rawClientData);
			writer.releaseLock();
			totalBytes += rawClientData.byteLength;

			// انتقال داده از سرور مقصد به کلاینت
			let headerSent = false;
			remoteSocket.readable.pipeTo(new WritableStream({
				write(chunk) {
					if (webSocket.readyState !== WS_READY_STATE_OPEN) return;
					if (!headerSent) {
						webSocket.send(new Blob([vlessRespHeader, chunk]).arrayBuffer ? chunk : chunk); // ارسال داده
						headerSent = true;
						webSocket.send(chunk);
					} else {
						webSocket.send(chunk);
					}
					totalBytes += chunk.byteLength;
				},
				close() { safeCloseWebSocket(webSocket); },
				abort() { safeCloseWebSocket(webSocket); },
			})).catch(() => safeCloseWebSocket(webSocket));
		},
		close() {
			// اتصال بسته شد -> ترافیک مصرفی کاربر را ثبت می‌کنیم
			trackUsage(user, totalBytes);
			saveUser(env, user).catch(() => {});
		},
	})).catch(() => {
		safeCloseWebSocket(webSocket);
	});

	return new Response(null, { status: 101, webSocket: client });
}

// ---------------------------------------------------------------
// تولید لینک‌های اشتراک (VLESS base64 و Clash YAML)
// ---------------------------------------------------------------

function buildVlessLink(cfg, user, remark) {
	const host = cfg.host;
	const sni = cfg.sni || host;
	const params = new URLSearchParams({
		type: 'ws',
		security: 'tls',
		sni,
		path: cfg.path,
		host,
	});
	if (cfg.fragment) params.set('fragment', cfg.fragment);
	if (cfg.ech) params.set('ech', cfg.ech);
	// پورت 443 چون فقط با TLS روی این پورت هندشیک واقعی و پینگ مثبت خواهیم داشت
	return `vless://${user.uuid}@${host}:443?${params.toString()}#${encodeURIComponent(remark)}`;
}

function buildSubscriptionBase64(cfg, user) {
	const link = buildVlessLink(cfg, user, `NovaProxy-${user.name || user.token.slice(0, 6)}`);
	return btoa(unescape(encodeURIComponent(link)));
}

function buildClashYAML(cfg, user) {
	const host = cfg.host;
	const sni = cfg.sni || host;
	return `proxies:
  - name: "NovaProxy-${user.name || user.token.slice(0, 6)}"
    type: vless
    server: ${host}
    port: 443
    uuid: ${user.uuid}
    network: ws
    tls: true
    udp: true
    servername: ${sni}
    ws-opts:
      path: "${cfg.path}"
      headers:
        Host: ${host}
proxy-groups:
  - name: "NovaProxy"
    type: select
    proxies:
      - "NovaProxy-${user.name || user.token.slice(0, 6)}"
rules:
  - MATCH,NovaProxy
`;
}

// ---------------------------------------------------------------
// Health-Check: قبل از فعال کردن یک HOST جدید، واقعاً تست می‌کنیم
// که TCP handshake روی پورت 443 آن انجام می‌شود (همان چیزی که
// باعث "پینگ مثبت" در کلاینت‌ها می‌شود).
// ---------------------------------------------------------------

async function tcpHealthCheck(hostOrIP, port = 443, timeoutMs = 3000) {
	const start = Date.now();
	try {
		const socket = connect({ hostname: hostOrIP, port });
		const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs));
		await Promise.race([socket.opened, timeout]);
		const latency = Date.now() - start;
		try { socket.close(); } catch (e) {}
		return { ok: true, latencyMs: latency };
	} catch (e) {
		return { ok: false, latencyMs: -1, error: String(e) };
	}
}

// این تابع توسط Cron صدا زده می‌شود: لیست IPهای کاندید ذخیره‌شده در KV را
// از داخل Worker تست می‌کند تا مطمئن شود *فعلی* هنوز روی 443 پاسخ می‌دهد
// و در صورت خراب بودن HOST فعلی، یکی از کاندیدهای سالم را جایگزین می‌کند.
// توجه: این فقط سلامتِ اتصال از Cloudflare-به-Cloudflare را می‌سنجد،
// نه سرعت از شبکه‌ی کاربر (آن بخش را پنل ادمین در مرورگر انجام می‌دهد).
async function runHealthCheckAndFailover(env) {
	const cfg = await getConfig(env);
	const candidates = cfg.candidateIPs.length ? cfg.candidateIPs : [cfg.host].filter(Boolean);

	const results = [];
	for (const ip of candidates) {
		const res = await tcpHealthCheck(ip, 443);
		results.push({ ip, ...res });
	}

	// آی‌پی فعلی را هم چک می‌کنیم
	const currentOK = cfg.host ? (await tcpHealthCheck(cfg.host, 443)).ok : false;

	if (!currentOK) {
		const healthy = results.filter(r => r.ok).sort((a, b) => a.latencyMs - b.latencyMs);
		if (healthy.length > 0) {
			const oldHost = cfg.host;
			cfg.host = healthy[0].ip;
			await addLog(env, 'auto-update', `HOST از ${oldHost || '(خالی)'} به ${cfg.host} تغییر کرد (Health-Check ناموفق روی قبلی)`);
		} else {
			await addLog(env, 'warning', 'هیچ‌کدام از IPهای کاندید سالم نبودند؛ HOST فعلی حفظ شد');
		}
	}

	cfg.lastScanAt = Date.now();
	cfg.lastScanResults = results;
	await saveConfig(env, cfg);
}

// ---------------------------------------------------------------
// پنل مدیریت (HTML/CSS/JS)
// ---------------------------------------------------------------

function loginPageHTML() {
	return `<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<title>ورود به پنل Nova Proxy</title>
<style>
body{font-family:Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#1e293b;padding:32px;border-radius:12px;width:300px;box-shadow:0 8px 24px rgba(0,0,0,.4)}
h2{margin-top:0;text-align:center}
input{width:100%;box-sizing:border-box;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff}
button{width:100%;padding:10px;border:none;border-radius:6px;background:#6366f1;color:#fff;font-weight:bold;cursor:pointer;margin-top:8px}
button:hover{background:#4f46e5}
.err{color:#f87171;text-align:center;font-size:13px;min-height:16px}
</style></head>
<body><div class="box">
<h2>🌌 Nova Proxy</h2>
<form id="f">
<input type="password" id="pass" placeholder="رمز ادمین" required>
<button type="submit">ورود</button>
<div class="err" id="err"></div>
</form></div>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
	e.preventDefault();
	const pass = document.getElementById('pass').value;
	const res = await fetch('/admin/api/login', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({pass}) });
	if (res.ok) { location.href = '/admin'; } else { document.getElementById('err').textContent = 'رمز اشتباه است'; }
});
</script>
</body></html>`;
}

function adminPageHTML() {
	// پنل کامل: مدیریت کاربران، تنظیمات HOST، Kill Switch، لاگ‌ها و اسکنر IP سمت مرورگر
	return `<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل مدیریت Nova Proxy</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--acc:#6366f1;--acc2:#22c55e;--danger:#ef4444;--text:#e2e8f0;--muted:#94a3b8}
*{box-sizing:border-box}
body{font-family:Tahoma,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:20px}
h1{font-size:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.card{background:var(--card);border-radius:12px;padding:18px;box-shadow:0 4px 16px rgba(0,0,0,.3)}
.card h3{margin-top:0;border-bottom:1px solid #334155;padding-bottom:8px}
input,select{width:100%;padding:8px;margin:4px 0;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff}
button{padding:8px 14px;border:none;border-radius:6px;background:var(--acc);color:#fff;cursor:pointer;margin:4px 2px}
button:hover{opacity:.9}
button.danger{background:var(--danger)}
button.green{background:var(--acc2)}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px;border-bottom:1px solid #334155;text-align:right}
.pill{padding:2px 8px;border-radius:20px;font-size:11px}
.pill.ok{background:#14532d;color:#86efac}
.pill.bad{background:#7f1d1d;color:#fca5a5}
.small{font-size:12px;color:var(--muted)}
.log{max-height:220px;overflow:auto;font-size:12px}
.kv{display:flex;justify-content:space-between;margin-top:8px}
</style></head>
<body>
<h1>🌌 پنل مدیریت Nova Proxy</h1>
<div class="grid">

  <div class="card">
    <h3>وضعیت کلی</h3>
    <div class="kv"><span>HOST فعلی:</span><b id="curHost">-</b></div>
    <div class="kv"><span>آخرین اسکن:</span><span id="lastScan">-</span></div>
    <div class="kv"><span>Kill Switch:</span><span id="ksStatus">-</span></div>
    <button class="danger" onclick="toggleKillSwitch()">تغییر وضعیت Kill Switch</button>
    <button onclick="runServerHealthCheck()">اجرای Health-Check دستی</button>
  </div>

  <div class="card">
    <h3>اسکن IP از شبکه‌ی شما (مرورگر)</h3>
    <p class="small">این تست از همین مرورگر/گوشی شما اجرا می‌شود، پس تأخیر واقعی شبکه‌ی خودتان را نشان می‌دهد؛ نه شبکه‌ی Cloudflare.</p>
    <textarea id="ipList" rows="4" placeholder="یک IP یا دامنه در هر خط"></textarea>
    <button onclick="scanFromBrowser()">شروع اسکن</button>
    <div id="scanResults" class="small"></div>
    <button class="green" onclick="applyBestIP()">اعمال بهترین IP به‌عنوان HOST</button>
  </div>

  <div class="card">
    <h3>تنظیمات اتصال</h3>
    <label class="small">PATH</label><input id="cfgPath">
    <label class="small">SNI (خالی = HOST)</label><input id="cfgSni">
    <label class="small">Fragment</label><input id="cfgFragment">
    <label class="small">ECH (اختیاری)</label><input id="cfgEch">
    <button onclick="saveCfg()">ذخیره تنظیمات</button>
  </div>

  <div class="card">
    <h3>افزودن کاربر جدید</h3>
    <input id="uName" placeholder="نام کاربر">
    <input id="uTrafficTotal" placeholder="سقف ترافیک کل (GB) - 0 = نامحدود" type="number">
    <input id="uTrafficDaily" placeholder="سقف ترافیک روزانه (GB) - 0 = نامحدود" type="number">
    <input id="uExpireDays" placeholder="انقضا (روز) - 0 = نامحدود" type="number">
    <button class="green" onclick="createUser()">ایجاد کاربر</button>
  </div>

  <div class="card" style="grid-column:1/-1">
    <h3>لیست کاربران</h3>
    <table id="usersTable">
      <thead><tr><th>نام</th><th>مصرف کل/سقف</th><th>مصرف امروز/سقف</th><th>انقضا</th><th>وضعیت</th><th>لینک اشتراک</th><th>عملیات</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card" style="grid-column:1/-1">
    <h3>لاگ فعالیت</h3>
    <div class="log" id="logBox"></div>
  </div>

</div>

<script>
async function api(path, opts) {
	const res = await fetch(path, Object.assign({ headers: { 'content-type': 'application/json' } }, opts || {}));
	if (res.status === 401) { location.href = '/admin'; return null; }
	return res.json().catch(() => ({}));
}

async function loadAll() {
	const cfg = await api('/admin/api/config');
	document.getElementById('curHost').textContent = cfg.host || '(تنظیم نشده)';
	document.getElementById('lastScan').textContent = cfg.lastScanAt ? new Date(cfg.lastScanAt).toLocaleString('fa-IR') : '-';
	document.getElementById('ksStatus').textContent = cfg.killSwitch ? '🔴 فعال (همه اتصالات قطع)' : '🟢 غیرفعال';
	document.getElementById('cfgPath').value = cfg.path || '';
	document.getElementById('cfgSni').value = cfg.sni || '';
	document.getElementById('cfgFragment').value = cfg.fragment || '';
	document.getElementById('cfgEch').value = cfg.ech || '';
	document.getElementById('ipList').value = (cfg.candidateIPs || []).join('\\n');

	const users = await api('/admin/api/users');
	const tbody = document.querySelector('#usersTable tbody');
	tbody.innerHTML = '';
	for (const u of users) {
		const tr = document.createElement('tr');
		const totalLimit = u.trafficLimitTotal ? (u.trafficLimitTotal/1e9).toFixed(1)+'GB' : '∞';
		const dailyLimit = u.trafficLimitDaily ? (u.trafficLimitDaily/1e9).toFixed(1)+'GB' : '∞';
		const exp = u.expiresAt ? new Date(u.expiresAt).toLocaleDateString('fa-IR') : 'نامحدود';
		tr.innerHTML = \`
			<td>\${u.name || u.token.slice(0,6)}</td>
			<td>\${((u.trafficUsedTotal||0)/1e9).toFixed(2)}GB / \${totalLimit}</td>
			<td>\${((u.trafficUsedDaily||0)/1e9).toFixed(2)}GB / \${dailyLimit}</td>
			<td>\${exp}</td>
			<td><span class="pill \${u.active?'ok':'bad'}">\${u.active?'فعال':'غیرفعال'}</span></td>
			<td><button onclick="copySub('\${u.token}')">کپی لینک</button></td>
			<td>
				<button onclick="toggleUser('\${u.token}')">فعال/غیرفعال</button>
				<button class="danger" onclick="removeUser('\${u.token}')">حذف</button>
			</td>\`;
		tbody.appendChild(tr);
	}

	const logs = await api('/admin/api/logs');
	document.getElementById('logBox').innerHTML = logs.map(l =>
		\`<div>[\${new Date(l.time).toLocaleTimeString('fa-IR')}] <b>\${l.type}</b>: \${l.message}</div>\`
	).join('');
}

async function saveCfg() {
	await api('/admin/api/config', { method: 'POST', body: JSON.stringify({
		path: document.getElementById('cfgPath').value,
		sni: document.getElementById('cfgSni').value,
		fragment: document.getElementById('cfgFragment').value,
		ech: document.getElementById('cfgEch').value,
		candidateIPs: document.getElementById('ipList').value.split('\\n').map(s=>s.trim()).filter(Boolean),
	})});
	loadAll();
}

async function toggleKillSwitch() { await api('/admin/api/killswitch', { method: 'POST' }); loadAll(); }
async function runServerHealthCheck() { await api('/admin/api/healthcheck', { method: 'POST' }); loadAll(); }

async function createUser() {
	await api('/admin/api/users', { method: 'POST', body: JSON.stringify({
		name: document.getElementById('uName').value,
		trafficLimitTotal: Number(document.getElementById('uTrafficTotal').value || 0) * 1e9,
		trafficLimitDaily: Number(document.getElementById('uTrafficDaily').value || 0) * 1e9,
		expireDays: Number(document.getElementById('uExpireDays').value || 0),
	})});
	loadAll();
}
async function toggleUser(token) { await api('/admin/api/users/' + token + '/toggle', { method: 'POST' }); loadAll(); }
async function removeUser(token) { if(confirm('حذف شود؟')) { await api('/admin/api/users/' + token, { method: 'DELETE' }); loadAll(); } }
async function copySub(token) {
	const url = location.origin + '/sub?token=' + token;
	await navigator.clipboard.writeText(url);
	alert('لینک اشتراک کپی شد:\\n' + url);
}

// ---- اسکنر IP سمت مرورگر (تأخیر واقعی شبکه‌ی کاربر) ----
let lastScanBest = null;
async function scanFromBrowser() {
	const ips = document.getElementById('ipList').value.split('\\n').map(s=>s.trim()).filter(Boolean);
	const resultsDiv = document.getElementById('scanResults');
	resultsDiv.innerHTML = 'در حال اسکن...';
	const results = [];
	for (const ip of ips) {
		const t0 = performance.now();
		try {
			// درخواست HEAD به cdn-cgi/trace که همه IPهای کلودفلر پاسخ می‌دهند (HTTPing واقعی)
			await fetch('https://' + ip + '/cdn-cgi/trace', { mode: 'no-cors', cache: 'no-store' });
			const latency = Math.round(performance.now() - t0);
			results.push({ ip, latency, ok: true });
		} catch (e) {
			results.push({ ip, latency: -1, ok: false });
		}
	}
	results.sort((a,b) => (a.ok?a.latency:1e9) - (b.ok?b.latency:1e9));
	lastScanBest = results.find(r => r.ok) || null;
	resultsDiv.innerHTML = results.map(r => \`\${r.ip}: \${r.ok ? r.latency+'ms' : 'ناموفق'}\`).join('<br>');
}
async function applyBestIP() {
	if (!lastScanBest) { alert('اول اسکن کنید'); return; }
	await api('/admin/api/apply-host', { method: 'POST', body: JSON.stringify({ host: lastScanBest.ip, latency: lastScanBest.latency }) });
	loadAll();
}

loadAll();
setInterval(loadAll, 15000);
</script>
</body></html>`;
}

// ---------------------------------------------------------------
// روتر اصلی درخواست‌های HTTP
// ---------------------------------------------------------------

async function handleAdminAPI(request, env, url) {
	const path = url.pathname;

	if (path === '/admin/api/login' && request.method === 'POST') {
		const { pass } = await request.json();
		if (pass !== env.ADMIN_PASS) return new Response('Unauthorized', { status: 401 });
		const token = await makeSessionToken(env);
		return new Response('OK', {
			headers: { 'Set-Cookie': `nova_session=${token}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax` }
		});
	}

	// همه‌ی روت‌های زیر نیاز به احراز هویت دارند
	if (!(await isAuthed(request, env))) return new Response('Unauthorized', { status: 401 });

	if (path === '/admin/api/config' && request.method === 'GET') {
		return Response.json(await getConfig(env));
	}
	if (path === '/admin/api/config' && request.method === 'POST') {
		const body = await request.json();
		const cfg = await getConfig(env);
		Object.assign(cfg, body);
		await saveConfig(env, cfg);
		await addLog(env, 'config', 'تنظیمات به‌روزرسانی شد');
		return Response.json({ ok: true });
	}
	if (path === '/admin/api/killswitch' && request.method === 'POST') {
		const cfg = await getConfig(env);
		cfg.killSwitch = !cfg.killSwitch;
		await saveConfig(env, cfg);
		await addLog(env, 'killswitch', cfg.killSwitch ? 'Kill Switch فعال شد' : 'Kill Switch غیرفعال شد');
		return Response.json({ ok: true, killSwitch: cfg.killSwitch });
	}
	if (path === '/admin/api/healthcheck' && request.method === 'POST') {
		await runHealthCheckAndFailover(env);
		return Response.json({ ok: true });
	}
	if (path === '/admin/api/apply-host' && request.method === 'POST') {
		const { host, latency } = await request.json();
		const cfg = await getConfig(env);
		const old = cfg.host;
		cfg.host = host;
		await saveConfig(env, cfg);
		await addLog(env, 'auto-update', `HOST دستی از پنل تغییر کرد: ${old || '(خالی)'} -> ${host} (پینگ اندازه‌گیری‌شده در مرورگر: ${latency}ms)`);
		return Response.json({ ok: true });
	}
	if (path === '/admin/api/logs' && request.method === 'GET') {
		return Response.json(await getLogs(env));
	}
	if (path === '/admin/api/users' && request.method === 'GET') {
		return Response.json(await listUsers(env));
	}
	if (path === '/admin/api/users' && request.method === 'POST') {
		const body = await request.json();
		const user = {
			token: uuidv4().replace(/-/g, ''),
			uuid: uuidv4(),
			name: body.name || '',
			active: true,
			trafficLimitTotal: body.trafficLimitTotal || 0,
			trafficLimitDaily: body.trafficLimitDaily || 0,
			trafficUsedTotal: 0,
			trafficUsedDaily: 0,
			dailyDate: new Date().toISOString().slice(0, 10),
			expiresAt: body.expireDays > 0 ? Date.now() + body.expireDays * 86400000 : 0,
			createdAt: Date.now(),
		};
		await saveUser(env, user);
		await addLog(env, 'user', `کاربر جدید ایجاد شد: ${user.name || user.token}`);
		return Response.json(user);
	}
	const toggleMatch = path.match(/^\/admin\/api\/users\/([^/]+)\/toggle$/);
	if (toggleMatch && request.method === 'POST') {
		const user = await getUser(env, toggleMatch[1]);
		if (!user) return new Response('Not found', { status: 404 });
		user.active = !user.active;
		await saveUser(env, user);
		await addLog(env, 'user', `وضعیت کاربر ${user.name || user.token} تغییر کرد: ${user.active ? 'فعال' : 'غیرفعال'}`);
		return Response.json({ ok: true });
	}
	const deleteMatch = path.match(/^\/admin\/api\/users\/([^/]+)$/);
	if (deleteMatch && request.method === 'DELETE') {
		await deleteUser(env, deleteMatch[1]);
		await addLog(env, 'user', `کاربر ${deleteMatch[1]} حذف شد`);
		return Response.json({ ok: true });
	}

	return new Response('Not found', { status: 404 });
}

async function handleSubscription(request, env, url) {
	const token = url.searchParams.get('token');
	if (!token) return new Response('token لازم است', { status: 400 });
	const user = await getUser(env, token);
	if (!user) return new Response('کاربر یافت نشد', { status: 404 });
	if (!isUserValid(user)) return new Response('اشتراک منقضی یا غیرفعال است', { status: 403 });

	const cfg = await getConfig(env);
	if (!cfg.host) return new Response('HOST هنوز تنظیم نشده؛ از پنل ادمین یک آی‌پی اعمال کنید', { status: 503 });

	const format = url.searchParams.get('format') || 'base64';
	if (format === 'clash' || format === 'yaml') {
		return new Response(buildClashYAML(cfg, user), { headers: { 'content-type': 'text/yaml; charset=utf-8' } });
	}
	return new Response(buildSubscriptionBase64(cfg, user), {
		headers: {
			'content-type': 'text/plain; charset=utf-8',
			// این هدرها به کلاینت اجازه می‌دهند اطلاعات ترافیک/انقضا را هم نمایش دهد
			'subscription-userinfo': `upload=0; download=${user.trafficUsedTotal || 0}; total=${user.trafficLimitTotal || 0}; expire=${user.expiresAt ? Math.floor(user.expiresAt / 1000) : 0}`,
		}
	});
}

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		// ---- اگر Kill Switch فعال است، همه اتصالات پروکسی رد می‌شوند ----
		const upgradeHeader = request.headers.get('Upgrade');

		try {
			// صفحه ورود و پنل ادمین
			if (url.pathname === '/admin') {
				if (!(await isAuthed(request, env))) return new Response(loginPageHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
				return new Response(adminPageHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
			}
			if (url.pathname.startsWith('/admin/api/')) {
				return await handleAdminAPI(request, env, url);
			}

			// لینک اشتراک
			if (url.pathname === '/sub') {
				return await handleSubscription(request, env, url);
			}

			// اتصال VLESS واقعی روی WebSocket
			if (upgradeHeader === 'websocket') {
				const cfg = await getConfig(env);
				if (cfg.killSwitch) return new Response('سرویس موقتاً غیرفعال است (Kill Switch)', { status: 503 });

				// شناسایی کاربر از روی UUID موجود در مسیر یا هدر (اینجا از query استفاده می‌کنیم)
				const token = url.searchParams.get('token');
				const user = token ? await getUser(env, token) : null;
				if (!user || !isUserValid(user)) {
					return new Response('دسترسی غیرمجاز', { status: 403 });
				}
				return await handleVlessWebSocket(request, env, user);
			}

			return new Response('Nova Proxy Worker فعال است.', { status: 200 });
		} catch (err) {
			await addLog(env, 'error', String(err && err.stack ? err.stack : err));
			return new Response('خطای داخلی: ' + String(err), { status: 500 });
		}
	},

	// ---- Cron Trigger: اسکن/Health-Check دوره‌ای و به‌روزرسانی خودکار HOST ----
	async scheduled(event, env, ctx) {
		ctx.waitUntil(runHealthCheckAndFailover(env));
	},
};
