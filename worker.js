
const PASSWORD_ITERATIONS = 100000;
const SESSION_DAYS = 7;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const SESSION_COOKIE = "artfive_session";
const MANAGER_SESSION_COOKIE = "artfive_manager_session";

const json = (data, status = 200, headers = {}) =>
  Response.json(data, { status, headers });

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return `pbkdf2$${PASSWORD_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, iterationsText, saltText, hashText] = String(stored || "").split("$");
    const iterations = Number(iterationsText);
    if (scheme !== "pbkdf2" || !Number.isInteger(iterations) || iterations < 100000 || iterations > 100000 || !saltText || !hashText) return false;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: base64ToBytes(saltText), iterations, hash: "SHA-256" },
      key,
      256
    );
    return safeEqual(bytesToBase64(new Uint8Array(bits)), hashText);
  } catch {
    return false;
  }
}

function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return "";
}

function sessionCookie(value, maxAge = SESSION_DAYS * 86400) {
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function managerSessionCookie(value, maxAge = 2 * 60 * 60) {
  return MANAGER_SESSION_COOKIE + "=" + encodeURIComponent(value) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge;
}

async function createManagerSession(owner, env, now) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const tokenHash = await sha256Base64(token);
  const expiresAt = now + 2 * 60 * 60 * 1000;
  await env.DB.prepare("DELETE FROM manager_sessions WHERE owner_id = ? OR expires_at <= ?").bind(owner.id, now).run();
  await env.DB.prepare("INSERT INTO manager_sessions (token_hash, owner_id, expires_at, created_at) VALUES (?, ?, ?, ?)").bind(tokenHash, owner.id, expiresAt, now).run();
  return token;
}

async function getManagerVerifiedOwner(request, env, now) {
  const owner = await getSessionUser(request, env, now);
  if (!owner || owner.role !== "owner") return null;
  const token = cookieValue(request, MANAGER_SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256Base64(token);
  const row = await env.DB.prepare(
    "SELECT owner_id FROM manager_sessions WHERE token_hash = ? AND owner_id = ? AND expires_at > ? LIMIT 1"
  ).bind(tokenHash, owner.id, now).first();
  return row ? owner : null;
}

function visitorDetails(request) {
  const ua = request.headers.get("User-Agent") || "";
  const cf = request.cf || {};
  const device = /ipad|tablet/i.test(ua) ? "Tablet" : /mobile|iphone|android/i.test(ua) ? "Mobile" : "Desktop";
  const operatingSystem = /windows/i.test(ua) ? "Windows" : /android/i.test(ua) ? "Android" : /iphone|ipad|ios/i.test(ua) ? "iOS" : /mac os|macintosh/i.test(ua) ? "macOS" : /linux/i.test(ua) ? "Linux" : "Unknown";
  const browser = /edg\//i.test(ua) ? "Edge" : /opr\//i.test(ua) ? "Opera" : /chrome\//i.test(ua) && !/edg\//i.test(ua) ? "Chrome" : /firefox\//i.test(ua) ? "Firefox" : /safari\//i.test(ua) && !/chrome\//i.test(ua) ? "Safari" : "Unknown";
  return { ua, device, operatingSystem, browser, city: cf.city || null, region: cf.region || cf.regionCode || null, country: cf.country || null, isp: cf.asOrganization || null };
}

async function ensureEngagementTables(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_engagement (
      id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK (action IN ('subscribe', 'rating')),
      rating INTEGER,
      created_at INTEGER NOT NULL,
      UNIQUE (customer_id, device_id, action)
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS app_installations (
      installation_id TEXT PRIMARY KEY,
      first_seen INTEGER NOT NULL
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS apk_downloads (
      id TEXT PRIMARY KEY,
      downloaded_at INTEGER NOT NULL,
      country TEXT,
      user_agent TEXT
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS apk_download_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      download_url TEXT NOT NULL,
      updated_by TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `).run();
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email || null,
    phone: user.phone || null,
    role: user.role
  };
}

async function readJson(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > MAX_BODY_BYTES) throw new Error("Request too large.");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) throw new Error("Request too large.");
  try { return text ? JSON.parse(text) : {}; } catch { throw new Error("Invalid JSON request."); }
}

async function logSecurity(env, ip, event, details, now) {
  try {
    await env.DB.prepare(
      `INSERT INTO security_logs (ip_address, event_type, details, created_at) VALUES (?, ?, ?, ?)`
    ).bind(ip, event, details, now).run();
  } catch { /* Security logging must not expose database details to visitors. */ }
}

async function loginRateLimited(env, ip, eventPrefix, now) {
  try {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT,
        created_at INTEGER NOT NULL
      )
    `).run();
    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM security_logs WHERE ip_address = ? AND event_type = ? AND created_at > ?"
    ).bind(ip, eventPrefix, now - 15 * 60 * 1000).first();
    return Number(row?.total || 0) >= 10;
  } catch {
    // Fail closed if the security log store cannot be checked.
    return true;
  }
}

async function getSessionUser(request, env, now) {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256Base64(token);
  const row = await env.DB.prepare(
    `SELECT users.id, users.name, users.email, users.phone, users.role, users.active
     FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.active = 1 LIMIT 1`
  ).bind(tokenHash, now).first();
  return row || null;
}

async function createSession(user, env, now) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToBase64(tokenBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const tokenHash = await sha256Base64(token);
  const expiresAt = now + SESSION_DAYS * 86400 * 1000;
  if (user.role === "owner") {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id).run();
  }
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`
  ).bind(tokenHash, user.id, expiresAt, now).run();
  return token;
}

async function deleteCurrentSession(request, env) {
  const token = cookieValue(request, SESSION_COOKIE);
  if (token) {
    const tokenHash = await sha256Base64(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).origin === new URL(request.url).origin; }
  catch { return false; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const now = Date.now();
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (path === "/download/app" && method === "GET") {
      try {
        const blockedDownload = await env.DB.prepare("SELECT ip_address FROM blocked_ips WHERE ip_address = ? AND (blocked_until IS NULL OR blocked_until > ?)").bind(ip, now).first();
        if (blockedDownload) return new Response("Access denied.", { status: 403, headers: { "Cache-Control": "no-store" } });
      } catch {
        return new Response("My ARTfive! Download security is temporarily unavailable.", { status: 503, headers: { "Cache-Control": "no-store" } });
      }
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS apk_download_settings (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          download_url TEXT NOT NULL,
          updated_by TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `).run();
      const downloadSetting = await env.DB.prepare("SELECT download_url FROM apk_download_settings WHERE id = 1").first();
      const configuredUrl = String(downloadSetting?.download_url || "").trim();
      if (!configuredUrl) return new Response("My ARTfive! APK download is not configured yet. Please contact the My ARTfive! team.", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
      let target;
      try {
        target = new URL(configuredUrl);
        const host = target.hostname.toLowerCase();
        const octets = host.split(".").map(Number);
        const validIpv4 = octets.length === 4 && octets.every(value => Number.isInteger(value) && value >= 0 && value <= 255);
        const privateIpv4 = validIpv4 && (octets[0] === 10 || (octets[0] === 192 && octets[1] === 168) || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31));
        const privateHost = host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") ||
          host === "127.0.0.1" || host === "::1" || privateIpv4;
        if (target.protocol !== "https:" || privateHost) throw new Error("Public HTTPS host required");
      } catch {
        return new Response("My ARTfive! APK download link is not configured correctly.", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
      }
      try {
        const upstream = await fetch(target.toString(), { redirect: "follow" });
        const upstreamType = String(upstream.headers.get("Content-Type") || "").toLowerCase();
        const upstreamLength = Number(upstream.headers.get("Content-Length") || 0);
        if (!upstream.ok || !upstream.body || upstreamType.includes("text/html") || (upstreamLength && upstreamLength > 150 * 1024 * 1024)) {
          return new Response("My ARTfive! The configured link did not return a valid APK file. Please use a direct HTTPS APK download URL.", { status: 502, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
        }
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS apk_downloads (
            id TEXT PRIMARY KEY,
            downloaded_at INTEGER NOT NULL,
            country TEXT,
            user_agent TEXT
          )
        `).run();
        await env.DB.prepare(
          "INSERT INTO apk_downloads (id, downloaded_at, country, user_agent) VALUES (?, ?, ?, ?)"
        ).bind(crypto.randomUUID(), now, request.cf?.country || null, (request.headers.get("User-Agent") || "").slice(0, 500)).run();
        const headers = new Headers({
          "Content-Type": "application/vnd.android.package-archive",
          "Content-Disposition": 'attachment; filename="My-ARTfive-Railway-Assistant.apk"',
          "Cache-Control": "no-store"
        });
        const contentLength = upstream.headers.get("Content-Length");
        if (contentLength) headers.set("Content-Length", contentLength);
        return new Response(upstream.body, { status: 200, headers });
      } catch (error) {
        console.error("My ARTfive! APK download failed:", error && error.message ? error.message : String(error));
        return new Response("My ARTfive! APK download failed. Please try again later.", { status: 502, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
      }
    }

    if (path.startsWith("/api/") && !isSameOrigin(request)) {
      return json({ success: false, message: "Cross-origin request blocked." }, 403);
    }

    if (path === "/api/health" && method === "GET") {
      try {
        await env.DB.prepare("SELECT 1").run();
        return json({ success: true, message: "My ARTfive! Worker and D1 are connected." });
      } catch {
        return json({ success: false, message: "Database connection failed." }, 503);
      }
    }

    if (!path.startsWith("/api/")) {
      if (method === "GET" && ip !== "unknown" && !/\.[a-z0-9]{1,8}$/i.test(path)) {
        try {
          const details = visitorDetails(request);
          const visitorKey = await sha256Base64(ip + "|" + details.ua);
          const signedIn = await getSessionUser(request, env, now);
          const visitorName = signedIn ? String(signedIn.name || "Unknown").slice(0, 100) : "Unknown";
          await env.DB.prepare(
            "INSERT INTO visitor_activity (visitor_key, ip_address, visitor_name, city, region, country, device, operating_system, browser, isp, first_seen, last_seen, visit_count, last_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?) ON CONFLICT(visitor_key) DO UPDATE SET ip_address = excluded.ip_address, visitor_name = CASE WHEN excluded.visitor_name != 'Unknown' THEN excluded.visitor_name ELSE visitor_activity.visitor_name END, city = excluded.city, region = excluded.region, country = excluded.country, device = excluded.device, operating_system = excluded.operating_system, browser = excluded.browser, isp = excluded.isp, last_seen = excluded.last_seen, visit_count = visitor_activity.visit_count + 1, last_path = excluded.last_path"
          ).bind(visitorKey, ip, visitorName, details.city, details.region, details.country, details.device, details.operatingSystem, details.browser, details.isp, now, now, path.slice(0, 500)).run();
          await env.DB.prepare("INSERT INTO visitor_page_views (visitor_key, ip_address, page_path, visited_at) VALUES (?, ?, ?, ?)").bind(visitorKey, ip, path.slice(0, 500), now).run();
        } catch (error) {
          console.warn("My ARTfive! visitor activity could not be recorded:", error && error.message ? error.message : String(error));
        }
      }
      return env.ASSETS.fetch(request);
    }

    try {
      if (ip !== "unknown") {
        const blocked = await env.DB.prepare(
          `SELECT ip_address FROM blocked_ips WHERE ip_address = ? AND (blocked_until IS NULL OR blocked_until > ?)`
        ).bind(ip, now).first();
        if (blocked) {
          await logSecurity(env, ip, "blocked_request", "Request rejected by IP block list", now);
          return json({ success: false, message: "Access denied." }, 403);
        }
      }
    } catch {
      return json({ success: false, message: "Security check unavailable." }, 503);
    }

    try {
      if (path === "/api/public/stats" && method === "GET") {
        await ensureEngagementTables(env);
        const [subscribers, ratings] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS total FROM customer_engagement WHERE action = 'subscribe'").first(),
          env.DB.prepare("SELECT COUNT(*) AS total FROM customer_engagement WHERE action = 'rating'").first()
        ]);
        return json({ success: true, subscribers: Number(subscribers?.total || 0), ratings: Number(ratings?.total || 0) });
      }

      if ((path === "/api/engagement/subscribe" || path === "/api/engagement/rating") && method === "POST") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "customer") return json({ success: false, message: "My ARTfive! Please sign in to your customer account before subscribing or rating." }, 401);
        const body = await readJson(request);
        const deviceId = String(body.deviceId || "").trim();
        if (!/^[A-Za-z0-9_-]{16,100}$/.test(deviceId)) return json({ success: false, message: "My ARTfive! This device could not be verified. Please refresh and try again." }, 400);
        await ensureEngagementTables(env);
        const action = path.endsWith("/subscribe") ? "subscribe" : "rating";
        const id = crypto.randomUUID();
        const result = await env.DB.prepare(
          "INSERT INTO customer_engagement (id, customer_id, device_id, action, rating, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(customer_id, device_id, action) DO NOTHING"
        ).bind(id, user.id, deviceId, action, action === "rating" ? 5 : null, now).run();
        const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM customer_engagement WHERE action = ?").bind(action).first();
        return json({ success: true, recorded: Number(result.meta?.changes || 0) > 0, count: Number(count?.total || 0) });
      }

      if (path === "/api/app/install" && method === "POST") {
        const body = await readJson(request);
        const installationId = String(body.installationId || "").trim();
        if (!/^[A-Za-z0-9_-]{16,100}$/.test(installationId)) return json({ success: false, message: "Invalid installation identifier." }, 400);
        await ensureEngagementTables(env);
        const result = await env.DB.prepare(
          "INSERT INTO app_installations (installation_id, first_seen) VALUES (?, ?) ON CONFLICT(installation_id) DO NOTHING"
        ).bind(installationId, now).run();
        const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM app_installations").first();
        return json({ success: true, recorded: Number(result.meta?.changes || 0) > 0, count: Number(count?.total || 0) });
      }

      if (path === "/api/owner/analysis" && method === "GET") {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can view private app analysis." }, 403);
        await ensureEngagementTables(env);
        const [users, subscribers, ratings, downloads] = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS total FROM users WHERE role = 'customer'").first(),
          env.DB.prepare("SELECT COUNT(*) AS total FROM customer_engagement WHERE action = 'subscribe'").first(),
          env.DB.prepare("SELECT COUNT(*) AS total FROM customer_engagement WHERE action = 'rating'").first(),
          env.DB.prepare("SELECT COUNT(*) AS total FROM apk_downloads").first()
        ]);
        return json({
          success: true,
          users: Number(users?.total || 0),
          subscribers: Number(subscribers?.total || 0),
          ratings: Number(ratings?.total || 0),
          downloads: Number(downloads?.total || 0)
        });
      }

      if (path === "/api/owner/apk-download-settings" && (method === "GET" || method === "POST")) {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can manage the APK download link." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS apk_download_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            download_url TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            updated_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const row = await env.DB.prepare("SELECT download_url AS downloadUrl FROM apk_download_settings WHERE id = 1").first();
          return json({ success: true, downloadUrl: row?.downloadUrl || "" });
        }
        const body = await readJson(request);
        const downloadUrl = String(body.downloadUrl || "").trim();
        if (!downloadUrl || downloadUrl.length > 2000) return json({ success: false, message: "Paste the direct HTTPS APK download URL." }, 400);
        let parsed;
        try { parsed = new URL(downloadUrl); } catch { return json({ success: false, message: "Enter a valid HTTPS download URL." }, 400); }
        if (parsed.protocol !== "https:") return json({ success: false, message: "Only HTTPS download URLs are accepted." }, 400);
        await env.DB.prepare(
          "INSERT INTO apk_download_settings (id, download_url, updated_by, updated_at) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET download_url = excluded.download_url, updated_by = excluded.updated_by, updated_at = excluded.updated_at"
        ).bind(downloadUrl, owner.id, now).run();
        return json({ success: true, downloadUrl, message: "My ARTfive! APK download link saved. Share the tracked app link with customers." });
      }

      if (path === "/api/customer-chat-settings" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to continue." }, 401);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_chat_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_by TEXT,
            updated_at INTEGER NOT NULL
          )
        `).run();
        await env.DB.prepare("INSERT INTO customer_chat_settings (id, enabled, updated_at) VALUES (1, 1, ?) ON CONFLICT(id) DO NOTHING").bind(now).run();
        if (method === "GET") {
          const row = await env.DB.prepare("SELECT enabled FROM customer_chat_settings WHERE id = 1").first();
          return json({ success: true, enabled: Number(row?.enabled ?? 1) === 1 });
        }
        if (user.role !== "owner") return json({ success: false, message: "Only the Owner can change customer chat access." }, 403);
        const body = await readJson(request);
        const enabled = body.enabled === true ? 1 : 0;
        await env.DB.prepare("UPDATE customer_chat_settings SET enabled = ?, updated_by = ?, updated_at = ? WHERE id = 1").bind(enabled, user.id, now).run();
        return json({ success: true, enabled: enabled === 1, message: enabled ? "My ARTfive! Customer enquiry replies are enabled." : "My ARTfive! Customer enquiry replies are paused." });
      }

      if (path === "/api/customer-enquiry" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "customer"].includes(user.role)) return json({ success: false, message: "Only the Owner and the signed-in customer can use this enquiry conversation." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_chat_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_by TEXT,
            updated_at INTEGER NOT NULL
          )
        `).run();
        await env.DB.prepare("INSERT INTO customer_chat_settings (id, enabled, updated_at) VALUES (1, 1, ?) ON CONFLICT(id) DO NOTHING").bind(now).run();
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_enquiry_messages (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_id TEXT NOT NULL REFERENCES users(id),
            sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff','customer')),
            sender_name TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
          )
        `).run();
        const body = method === "POST" ? await readJson(request) : {};
        const targetCustomerId = user.role === "customer" ? user.id : String(body.customerId || url.searchParams.get("customerId") || "").trim();
        if (!targetCustomerId) return json({ success: false, message: "Select the customer enquiry conversation." }, 400);
        const target = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND role = 'customer' AND active = 1 LIMIT 1").bind(targetCustomerId).first();
        if (!target) return json({ success: false, message: "Customer account was not found." }, 404);
        if (method === "GET") {
          const rows = await env.DB.prepare(
            "SELECT id, sender_role AS senderRole, sender_name AS sender, message AS text, created_at AS createdAt FROM customer_enquiry_messages WHERE customer_id = ? ORDER BY created_at ASC LIMIT 300"
          ).bind(targetCustomerId).all();
          return json({ success: true, messages: rows.results || [] });
        }
        if (user.role === "customer") {
          const chatSetting = await env.DB.prepare("SELECT enabled FROM customer_chat_settings WHERE id = 1").first();
          if (chatSetting && Number(chatSetting.enabled) !== 1) return json({ success: false, message: "My ARTfive! Customer replies are temporarily paused. You can still view existing messages." }, 403);
        }
        const messageText = String(body.message || "").trim();
        if (!messageText || messageText.length > 2000) return json({ success: false, message: "Enter a message up to 2,000 characters." }, 400);
        if (user.role === "customer" && !messageText) return json({ success: false, message: "Enter your enquiry." }, 400);
        const senderName = user.role === "customer" ? user.name : "My ARTfive!";
        const finalMessage = user.role === "customer" ? messageText : (/^My ARTfive!/i.test(messageText) ? messageText : "My ARTfive! " + messageText);
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO customer_enquiry_messages (id, customer_id, sender_id, sender_role, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, targetCustomerId, user.id, user.role, senderName, finalMessage, now).run();
        return json({ success: true, id, message: "My ARTfive! Enquiry message saved." }, 201);
      }

      if (path === "/api/staff-chat" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) return json({ success: false, message: "Only Owner and Staff can access Staff Chat." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS staff_chat_messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL REFERENCES users(id),
            sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff')),
            sender_name TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const rows = await env.DB.prepare(
            "SELECT id, sender_role AS senderRole, sender_name AS sender, message AS text, created_at AS createdAt FROM staff_chat_messages ORDER BY created_at ASC LIMIT 300"
          ).all();
          return json({ success: true, messages: rows.results || [] });
        }
        const body = await readJson(request);
        const messageText = String(body.message || "").trim();
        if (!messageText || messageText.length > 2000) return json({ success: false, message: "Enter a message up to 2,000 characters." }, 400);
        const senderName = user.role === "owner" ? "My ARTfive!" : user.name;
        const finalMessage = user.role === "owner" && !/^My ARTfive!/i.test(messageText) ? "My ARTfive! " + messageText : messageText;
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO staff_chat_messages (id, sender_id, sender_role, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(id, user.id, user.role, senderName, finalMessage, now).run();
        return json({ success: true, id, message: "My ARTfive! Staff message saved." }, 201);
      }

      if (path === "/api/public/cms" && method === "GET") {
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
        const row = await env.DB.prepare("SELECT setting_json FROM app_settings WHERE setting_key = 'master_cms' LIMIT 1").first();
        if (!row) return json({ success: true, settings: null });
        try { return json({ success: true, settings: JSON.parse(row.setting_json) }); }
        catch { return json({ success: true, settings: null }); }
      }

      if (path === "/api/owner/cms" && (method === "GET" || method === "POST")) {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can manage Master CMS settings." }, 403);
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
        if (method === "GET") {
          const row = await env.DB.prepare("SELECT setting_json FROM app_settings WHERE setting_key = 'master_cms' LIMIT 1").first();
          if (!row) return json({ success: true, settings: null });
          try { return json({ success: true, settings: JSON.parse(row.setting_json) }); }
          catch { return json({ success: false, message: "Saved Master CMS data could not be read." }, 500); }
        }
        const body = await readJson(request);
        if (!body.settings || typeof body.settings !== "object" || Array.isArray(body.settings)) return json({ success: false, message: "Master CMS settings are missing." }, 400);
        const settingJson = JSON.stringify(body.settings);
        if (settingJson.length > 2500000) return json({ success: false, message: "Master CMS data is too large. Reduce image sizes and try again." }, 413);
        await env.DB.prepare(
          "INSERT INTO app_settings (setting_key, setting_json, updated_by, updated_at) VALUES ('master_cms', ?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_json = excluded.setting_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at"
        ).bind(settingJson, owner.id, now).run();
        return json({ success: true, message: "My ARTfive! Master CMS changes have been saved centrally for all devices." });
      }

      if (path === "/api/app-updates" && (method === "GET" || method === "POST")) {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS app_updates (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            created_by TEXT NOT NULL REFERENCES users(id),
            created_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const rows = await env.DB.prepare("SELECT id, title, description, created_at AS createdAt FROM app_updates ORDER BY created_at DESC LIMIT 100").all();
          return json({ success: true, updates: rows.results || [] });
        }
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can publish app updates." }, 403);
        const body = await readJson(request);
        const title = String(body.title || "").trim();
        let description = String(body.description || "").trim();
        if (!title || !description || title.length > 160 || description.length > 2000) return json({ success: false, message: "Enter a title and description within the allowed length." }, 400);
        if (!/^My ARTfive!/i.test(description)) description = "My ARTfive! " + description;
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO app_updates (id, title, description, created_by, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, title, description, owner.id, now).run();
        return json({ success: true, id, message: "My ARTfive! App update published successfully." }, 201);
      }

      if (path === "/api/notifications" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to view My ARTfive! notifications." }, 401);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_notifications (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_id TEXT NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            read_at INTEGER
          )
        `).run();
        if (method === "GET") {
          if (user.role === "customer") {
            const rows = await env.DB.prepare(
              "SELECT id, message, created_at AS createdAt, read_at AS readAt FROM customer_notifications WHERE customer_id = ? ORDER BY created_at DESC LIMIT 100"
            ).bind(user.id).all();
            return json({ success: true, notifications: rows.results || [] });
          }
          if (user.role === "owner") {
            const rows = await env.DB.prepare(
              "SELECT n.id, n.customer_id AS customerId, u.name AS customerName, u.phone AS customerPhone, n.message, n.created_at AS createdAt, n.read_at AS readAt FROM customer_notifications n JOIN users u ON u.id = n.customer_id ORDER BY n.created_at DESC LIMIT 300"
            ).all();
            return json({ success: true, notifications: rows.results || [] });
          }
          return json({ success: false, message: "Access denied." }, 403);
        }
        if (user.role !== "owner") return json({ success: false, message: "Only the Owner can send customer notifications." }, 403);
        const body = await readJson(request);
        let message = String(body.message || "").trim();
        const customerId = String(body.customerId || "").trim();
        const category = String(body.category || "All");
        if (!message || message.length > 2000) return json({ success: false, message: "Enter a notification message up to 2,000 characters." }, 400);
        if (!/^My ARTfive!/i.test(message)) message = "My ARTfive! " + message;
        let recipients;
        if (customerId) {
          recipients = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND role = 'customer' AND active = 1 LIMIT 1").bind(customerId).all();
        } else if (category === "Subscribers") {
          await ensureEngagementTables(env);
          recipients = await env.DB.prepare("SELECT DISTINCT u.id FROM users u JOIN customer_engagement e ON e.customer_id = u.id WHERE u.role = 'customer' AND u.active = 1 AND e.action = 'subscribe'").all();
        } else if (category === "Pending") {
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS customer_payment_instructions (
              id TEXT PRIMARY KEY,
              request_id TEXT NOT NULL,
              customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              option_no INTEGER NOT NULL CHECK (option_no IN (2, 3)),
              amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
              message TEXT NOT NULL,
              updated_by TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              payment_status TEXT NOT NULL DEFAULT 'pending',
              verified_by TEXT,
              verified_at INTEGER,
              UNIQUE (request_id, option_no)
            )
          `).run();
          const columnsResult = await env.DB.prepare("PRAGMA table_info(customer_payment_instructions)").all();
          const columns = new Set((columnsResult.results || []).map(column => column.name));
          if (!columns.has("payment_status")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending'").run();
          if (!columns.has("verified_by")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_by TEXT").run();
          if (!columns.has("verified_at")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_at INTEGER").run();
          recipients = await env.DB.prepare(
            "SELECT DISTINCT u.id FROM users u JOIN requests r ON r.customer_id = u.id WHERE u.role = 'customer' AND u.active = 1 AND NOT EXISTS (SELECT 1 FROM customer_payment_instructions p WHERE p.request_id = r.id AND p.option_no = 3 AND p.payment_status = 'verified')"
          ).all();
        } else {
          recipients = await env.DB.prepare("SELECT id FROM users WHERE role = 'customer' AND active = 1").all();
        }
        const recipientRows = recipients.results || [];
        if (!recipientRows.length) return json({ success: true, sent: 0, message: "My ARTfive! There are no customers in the selected notification group." });
        if (recipientRows.length > 1000) return json({ success: false, message: "The selected notification group is too large. Please send to a smaller group." }, 413);
        for (const recipient of recipientRows) {
          await env.DB.prepare(
            "INSERT INTO customer_notifications (id, customer_id, sender_id, message, created_at) VALUES (?, ?, ?, ?, ?)"
          ).bind(crypto.randomUUID(), recipient.id, user.id, message, now).run();
        }
        return json({ success: true, sent: recipientRows.length, message: "My ARTfive! Notification saved for " + recipientRows.length + " customer(s)." }, 201);
      }

      if (path === "/api/me" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Not signed in." }, 401);
        return json({ success: true, user: publicUser(user) });
      }

      if (path === "/api/owner/status" && method === "GET") {
        const owner = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();
        return json({ success: true, ownerExists: !!owner });
      }

      if (path === "/api/owner/setup" && method === "POST") {
        if (!env.OWNER_SETUP_KEY) return json({ success: false, message: "Owner setup is not configured." }, 503);
        const body = await readJson(request);
        if (!safeEqual(String(body.setupKey || ""), String(env.OWNER_SETUP_KEY))) {
          await logSecurity(env, ip, "owner_setup_denied", "Invalid owner setup key", now);
          return json({ success: false, message: "Invalid setup key." }, 403);
        }
        const existing = await env.DB.prepare("SELECT id FROM users WHERE role = 'owner' LIMIT 1").first();
        if (existing) return json({ success: false, message: "An owner account already exists. A second Owner cannot be created." }, 409);
        const name = String(body.name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12) {
          return json({ success: false, message: "Enter a valid email, name and a password of at least 12 characters." }, 400);
        }
        if (name.length > 100 || email.length > 254) return json({ success: false, message: "Some details are too long." }, 400);
        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(
          `INSERT INTO users (id, name, email, phone, role, password_hash, active, created_at)
           VALUES (?, ?, ?, NULL, 'owner', ?, 1, ?)`
        ).bind(id, name, email, passwordHash, now).run();
        await logSecurity(env, ip, "owner_setup_success", "Owner account created", now);
        return json({ success: true, message: "Owner account created securely. Please sign in." }, 201);
      }

      if (path === "/api/owner/manager/status" && method === "GET") {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can access Manager security." }, 403);
        const row = await env.DB.prepare("SELECT owner_id FROM manager_credentials WHERE owner_id = ? LIMIT 1").bind(owner.id).first();
        return json({ success: true, configured: !!row });
      }

      if (path === "/api/owner/manager/verify" && method === "POST") {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") {
          await logSecurity(env, ip, "manager_access_denied", "Non-owner attempted Manager verification", now);
          return json({ success: false, message: "Only the Owner can access Manager." }, 403);
        }
        const body = await readJson(request);
        const phone = String(body.phone || "").trim();
        const password = String(body.password || "");
        if (!phone || !password || phone.length > 30 || password.length > 256) {
          return json({ success: false, message: "Enter the registered phone number and password." }, 400);
        }
        const existing = await env.DB.prepare(
          "SELECT phone, password_hash FROM manager_credentials WHERE owner_id = ? LIMIT 1"
        ).bind(owner.id).first();
        if (existing) {
          if (!safeEqual(existing.phone, phone) || !(await verifyPassword(password, existing.password_hash))) {
            await logSecurity(env, ip, "manager_login_failed", "Invalid Manager credentials", now);
            return json({ success: false, message: "Phone number or password was not accepted." }, 401);
          }
        } else {
          if (password.length < 12) return json({ success: false, message: "For security, your Manager password must contain at least 12 characters." }, 400);
          const passwordHash = await hashPassword(password);
          await env.DB.prepare(
            "INSERT INTO manager_credentials (owner_id, phone, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
          ).bind(owner.id, phone, passwordHash, now, now).run();
          await logSecurity(env, ip, "manager_credentials_created", "Manager credentials securely stored in D1", now);
        }
        await logSecurity(env, ip, "manager_login_success", "Owner verified for Manager", now);
        const managerToken = await createManagerSession(owner, env, now);
        return json({ success: true, message: "My ARTfive! Manager security verified." }, 200, { "Set-Cookie": managerSessionCookie(managerToken) });
      }

      if (path === "/api/owner/manager/reset" && method === "POST") {
        const ownerSession = await getSessionUser(request, env, now);
        if (!ownerSession || ownerSession.role !== "owner") {
          await logSecurity(env, ip, "manager_password_reset_denied", "Non-owner attempted Manager password recovery", now);
          return json({ success: false, message: "Only the signed-in Owner can recover Manager access." }, 403);
        }
        const body = await readJson(request);
        const ownerPassword = String(body.owner_password || "");
        const newPassword = String(body.new_password || "");
        if (!ownerPassword || newPassword.length < 12 || newPassword.length > 256) {
          return json({ success: false, message: "Enter your Owner account password and a new Manager password of at least 12 characters." }, 400);
        }
        const ownerRecord = await env.DB.prepare(
          "SELECT password_hash FROM users WHERE id = ? AND role = 'owner' AND active = 1 LIMIT 1"
        ).bind(ownerSession.id).first();
        if (!ownerRecord || !(await verifyPassword(ownerPassword, ownerRecord.password_hash))) {
          await logSecurity(env, ip, "manager_password_reset_failed", "Owner password verification failed during Manager recovery", now);
          return json({ success: false, message: "Owner account password was not accepted. Manager password was not changed." }, 401);
        }
        const managerRecord = await env.DB.prepare(
          "SELECT owner_id FROM manager_credentials WHERE owner_id = ? LIMIT 1"
        ).bind(ownerSession.id).first();
        if (!managerRecord) {
          return json({ success: false, message: "Manager credentials are not configured yet. Open Option 11 to set them up first." }, 404);
        }
        const passwordHash = await hashPassword(newPassword);
        await env.DB.prepare(
          "UPDATE manager_credentials SET password_hash = ?, updated_at = ? WHERE owner_id = ?"
        ).bind(passwordHash, now, ownerSession.id).run();
        await env.DB.prepare("DELETE FROM manager_sessions WHERE owner_id = ?").bind(ownerSession.id).run();
        await logSecurity(env, ip, "manager_password_reset_success", "Owner reset Manager password after Owner password verification", now);
        return json({ success: true, message: "My ARTfive! Manager password reset successfully. Your existing Manager phone number is unchanged. Verify again using the new password." });
      }

      if (path === "/api/owner/manager/code-draft" && (method === "GET" || method === "POST")) {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required to access code drafts." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS manager_code_drafts (
            owner_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            source_code TEXT NOT NULL,
            updated_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const row = await env.DB.prepare("SELECT source_code AS sourceCode, updated_at AS updatedAt FROM manager_code_drafts WHERE owner_id = ? LIMIT 1").bind(owner.id).first();
          return json({ success: true, sourceCode: row?.sourceCode || "", updatedAt: row?.updatedAt || null });
        }
        const body = await readJson(request);
        const sourceCode = String(body.sourceCode || "");
        if (!sourceCode.trim() || sourceCode.length > 500000) return json({ success: false, message: "Enter code up to 500,000 characters." }, 400);
        await env.DB.prepare(
          "INSERT INTO manager_code_drafts (owner_id, source_code, updated_at) VALUES (?, ?, ?) ON CONFLICT(owner_id) DO UPDATE SET source_code = excluded.source_code, updated_at = excluded.updated_at"
        ).bind(owner.id, sourceCode, now).run();
        return json({ success: true, message: "My ARTfive! Code draft saved securely. Production deployment has NOT been performed." });
      }

      if (path === "/api/owner/control/visitors" && method === "GET") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required for Control." }, 403);
        const result = await env.DB.prepare(
          "SELECT v.visitor_key, v.ip_address, v.visitor_name, v.city, v.region, v.country, v.device, v.operating_system, v.browser, v.isp, v.first_seen, v.last_seen, v.visit_count, v.last_path, COALESCE(p.pages_visited, '') AS pages_visited, COALESCE(l.login_attempts, 0) AS login_attempts, CASE WHEN b.ip_address IS NULL THEN 0 ELSE 1 END AS is_blocked FROM visitor_activity v LEFT JOIN blocked_ips b ON b.ip_address = v.ip_address LEFT JOIN (SELECT visitor_key, GROUP_CONCAT(DISTINCT page_path) AS pages_visited FROM visitor_page_views GROUP BY visitor_key) p ON p.visitor_key = v.visitor_key LEFT JOIN (SELECT ip_address, COUNT(*) AS login_attempts FROM security_logs WHERE event_type LIKE '%login_failed%' GROUP BY ip_address) l ON l.ip_address = v.ip_address ORDER BY v.last_seen DESC LIMIT 500"
        ).all();
        const totals = await env.DB.prepare("SELECT COUNT(*) AS visitors, COALESCE(SUM(visit_count), 0) AS visits FROM visitor_activity").first();
        const blocked = await env.DB.prepare("SELECT COUNT(*) AS count FROM blocked_ips WHERE blocked_until IS NULL OR blocked_until > ?").bind(now).first();
        const blockedIps = await env.DB.prepare("SELECT ip_address, reason, created_at, blocked_until FROM blocked_ips WHERE blocked_until IS NULL OR blocked_until > ? ORDER BY created_at DESC LIMIT 500").bind(now).all();
        return json({ success: true, visitors: result.results || [], blockedIps: blockedIps.results || [], totals: totals || { visitors: 0, visits: 0 }, blockedCount: blocked ? blocked.count : 0 });
      }

      if (path === "/api/password-change/request" && method === "POST") {
        if (await loginRateLimited(env, ip, "password_change_request", now)) {
          return json({ success: false, message: "My ARTfive! Too many password change requests. Please try again later." }, 429);
        }
        const body = await readJson(request);
        const phone = String(body.phone || "").trim();
        const role = String(body.role || "").trim();
        const newPassword = String(body.newPassword || "");
        if (!phone || phone.length > 30 || !["customer", "staff"].includes(role) || newPassword.length < 8 || newPassword.length > 256) {
          return json({ success: false, message: "My ARTfive! Enter your registered phone number and a new password of at least 8 characters." }, 400);
        }
        const account = await env.DB.prepare(
          "SELECT id FROM users WHERE phone = ? AND role = ? AND active = 1 LIMIT 1"
        ).bind(phone, role).first();
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS password_change_requests (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            phone TEXT NOT NULL,
            requested_password_hash TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            reviewed_by TEXT
          )
        `).run();
        const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
        const token = bytesToBase64(tokenBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
        const tokenHash = await sha256Base64(token);
        const passwordHash = await hashPassword(newPassword);
        if (account) {
          await env.DB.prepare(
            "UPDATE password_change_requests SET status = 'superseded', reviewed_at = ? WHERE user_id = ? AND status = 'pending'"
          ).bind(now, account.id).run();
        }
        await env.DB.prepare(
          "INSERT INTO password_change_requests (id, status, user_id, role, phone, requested_password_hash, token_hash, created_at) VALUES (?, 'pending', ?, ?, ?, ?, ?, ?)"
        ).bind(crypto.randomUUID(), account?.id || null, role, phone, passwordHash, tokenHash, now).run();
        await logSecurity(env, ip, "password_change_request", "Password change approval request submitted", now);
        return json({
          success: true,
          token,
          message: "My ARTfive! Your password change request has been sent to the Owner for approval."
        }, 201);
      }

      if (path === "/api/password-change/status" && method === "GET") {
        const token = String(url.searchParams.get("token") || "");
        if (!/^[A-Za-z0-9_\\-]{30,100}$/.test(token)) return json({ success: false, message: "Invalid request reference." }, 400);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS password_change_requests (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            phone TEXT NOT NULL,
            requested_password_hash TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            reviewed_by TEXT
          )
        `).run();
        const tokenHash = await sha256Base64(token);
        const row = await env.DB.prepare(
          "SELECT status FROM password_change_requests WHERE token_hash = ? LIMIT 1"
        ).bind(tokenHash).first();
        return json({ success: true, status: row?.status || "pending" });
      }

      if (path === "/api/owner/control/password-requests" && method === "GET") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required for Control." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS password_change_requests (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            phone TEXT NOT NULL,
            requested_password_hash TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            reviewed_by TEXT
          )
        `).run();
        const rows = await env.DB.prepare(
          "SELECT r.id, r.role, r.phone, u.name, r.created_at AS createdAt FROM password_change_requests r JOIN users u ON u.id = r.user_id WHERE r.status = 'pending' ORDER BY r.created_at ASC LIMIT 200"
        ).all();
        return json({ success: true, requests: rows.results || [] });
      }

      if (path === "/api/owner/control/password-requests/decision" && method === "POST") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required for Control." }, 403);
        const body = await readJson(request);
        const requestId = String(body.requestId || "");
        const decision = String(body.decision || "");
        if (!requestId || !["approve", "reject"].includes(decision)) {
          return json({ success: false, message: "Choose Approve or Reject for a valid request." }, 400);
        }
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS password_change_requests (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            phone TEXT NOT NULL,
            requested_password_hash TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER,
            reviewed_by TEXT
          )
        `).run();
        const row = await env.DB.prepare(
          "SELECT r.id, r.user_id, r.requested_password_hash FROM password_change_requests r JOIN users u ON u.id = r.user_id AND u.active = 1 WHERE r.id = ? AND r.status = 'pending' LIMIT 1"
        ).bind(requestId).first();
        if (!row || !row.user_id) return json({ success: false, message: "This password change request is no longer available." }, 409);
        const nextStatus = decision === "approve" ? "approved" : "rejected";
        const statements = [];
        if (decision === "approve") {
          statements.push(env.DB.prepare(
            "UPDATE users SET password_hash = ? WHERE id = ? AND active = 1 AND EXISTS (SELECT 1 FROM password_change_requests WHERE id = ? AND status = 'pending' AND user_id = ?)"
          ).bind(row.requested_password_hash, row.user_id, requestId, row.user_id));
        }
        statements.push(env.DB.prepare(
          "UPDATE password_change_requests SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending' AND user_id IS NOT NULL"
        ).bind(nextStatus, now, owner.id, requestId));
        const results = await env.DB.batch(statements);
        const decisionResult = results[results.length - 1];
        if (!Number(decisionResult?.meta?.changes || 0)) {
          return json({ success: false, message: "This password change request has already been handled." }, 409);
        }
        if (decision === "approve" && !Number(results[0]?.meta?.changes || 0)) {
          return json({ success: false, message: "The account is no longer active. The password was not changed." }, 409);
        }
        await logSecurity(env, ip, "password_change_" + decision, "Owner " + decision + "d a password change request", now);
        return json({ success: true, status: nextStatus, message: decision === "approve" ? "My ARTfive! Password change approved." : "My ARTfive! Request decision saved." });
      }

      if (path === "/api/owner/control/block" && method === "POST") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required for Control." }, 403);
        const body = await readJson(request);
        const targetIp = String(body.ip_address || "").trim();
        const reason = String(body.reason || "Blocked by My ARTfive! Owner").trim().slice(0, 250);
        if (!targetIp || targetIp === "unknown" || targetIp.length > 64) return json({ success: false, message: "A valid visitor IP address is required." }, 400);
        if (targetIp === ip) return json({ success: false, message: "You cannot block your current connection." }, 400);
        await env.DB.prepare("INSERT INTO blocked_ips (ip_address, blocked_until, reason, created_at) VALUES (?, NULL, ?, ?) ON CONFLICT(ip_address) DO UPDATE SET blocked_until = NULL, reason = excluded.reason, created_at = excluded.created_at").bind(targetIp, reason, now).run();
        await logSecurity(env, ip, "visitor_ip_blocked", "Owner blocked visitor IP " + targetIp, now);
        return json({ success: true, message: "My ARTfive! Visitor access blocked." });
      }

      if (path === "/api/owner/control/unblock" && method === "POST") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required for Control." }, 403);
        const body = await readJson(request);
        const targetIp = String(body.ip_address || "").trim();
        if (!targetIp || targetIp.length > 64) return json({ success: false, message: "A valid visitor IP address is required." }, 400);
        await env.DB.prepare("DELETE FROM blocked_ips WHERE ip_address = ?").bind(targetIp).run();
        await logSecurity(env, ip, "visitor_ip_unblocked", "Owner unblocked visitor IP " + targetIp, now);
        return json({ success: true, message: "My ARTfive! Visitor access unblocked." });
      }

      if (path === "/api/owner/login" && method === "POST") {
        if (await loginRateLimited(env, ip, "staff_owner_login_failed", now)) return json({ success: false, message: "Too many sign-in attempts. Please wait 15 minutes and try again." }, 429);
        const body = await readJson(request);
        const identifier = String(body.identifier || "").trim();
        const password = String(body.password || "");
        if (!identifier || !password) return json({ success: false, message: "Enter your email and password." }, 400);
        const user = await env.DB.prepare(
          `SELECT id, name, email, phone, role, password_hash, active FROM users
           WHERE (role = 'owner' AND lower(email) = lower(?))
              OR (role = 'staff' AND (lower(email) = lower(?) OR phone = ?))
           ORDER BY CASE WHEN role = 'owner' THEN 0 ELSE 1 END LIMIT 1`
        ).bind(identifier, identifier, identifier).first();
        if (!user || user.active !== 1 || !(await verifyPassword(password, user.password_hash))) {
          await logSecurity(env, ip, "staff_owner_login_failed", "Invalid Owner/Staff sign-in", now);
          return json({ success: false, message: "Email or password was not accepted." }, 401);
        }
        const token = await createSession(user, env, now);
        await logSecurity(env, ip, "staff_owner_login_success", `${user.role} signed in`, now);
        return json({ success: true, user: publicUser(user) }, 200, { "Set-Cookie": sessionCookie(token) });
      }

      if ((path === "/api/owner/logout" || path === "/api/logout") && method === "POST") {
        await deleteCurrentSession(request, env);
        return json({ success: true, message: "Signed out." }, 200, { "Set-Cookie": sessionCookie("", 0) });
      }

      if (path === "/api/customer/register" && method === "POST") {
        if (await loginRateLimited(env, ip, "customer_register_attempt", now)) return json({ success: false, message: "Too many sign-up attempts. Please wait 15 minutes and try again." }, 429);
        await logSecurity(env, ip, "customer_register_attempt", "Customer registration attempt", now);
        const body = await readJson(request);
        const name = String(body.name || "").trim();
        const phone = String(body.phone || "").trim();
        const password = String(body.password || "");
        if (!name || !phone || password.length < 8) return json({ success: false, message: "Enter your name, phone number and a password of at least 8 characters." }, 400);
        if (name.length > 100 || phone.length > 30) return json({ success: false, message: "Some details are too long." }, 400);
        const existing = await env.DB.prepare("SELECT id FROM users WHERE phone = ? LIMIT 1").bind(phone).first();
        if (existing) {
          await logSecurity(env, ip, "customer_register_failed", "Duplicate customer phone registration attempt", now);
          return json({ success: false, message: "This phone number is already registered. Please sign in." }, 409);
        }
        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(
          `INSERT INTO users (id, name, email, phone, role, password_hash, active, created_at)
           VALUES (?, ?, NULL, ?, 'customer', ?, 1, ?)`
        ).bind(id, name, phone, passwordHash, now).run();
        return json({ success: true, message: "My ARTfive! Customer account created successfully." }, 201);
      }

      if (path === "/api/customer/login" && method === "POST") {
        if (await loginRateLimited(env, ip, "customer_login_failed", now)) return json({ success: false, message: "Too many sign-in attempts. Please wait 15 minutes and try again." }, 429);
        const body = await readJson(request);
        const phone = String(body.phone || "").trim();
        const password = String(body.password || "");
        if (!phone || !password) return json({ success: false, message: "Enter your phone number and password." }, 400);
        const user = await env.DB.prepare(
          `SELECT id, name, email, phone, role, password_hash, active FROM users WHERE phone = ? AND role = 'customer' LIMIT 1`
        ).bind(phone).first();
        if (!user || user.active !== 1 || !(await verifyPassword(password, user.password_hash))) {
          await logSecurity(env, ip, "customer_login_failed", "Invalid customer sign-in", now);
          return json({ success: false, message: "Phone number or password was not accepted." }, 401);
        }
        const token = await createSession(user, env, now);
        const response = { success: true, user: publicUser(user) };
        if (body.ticketAccess === true) {
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS customer_ticket_access (
              token_hash TEXT PRIMARY KEY,
              customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              expires_at INTEGER NOT NULL,
              created_at INTEGER NOT NULL
            )
          `).run();
          const accessBytes = crypto.getRandomValues(new Uint8Array(32));
          const ticketAccessToken = bytesToBase64(accessBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
          const accessHash = await sha256Base64(ticketAccessToken);
          await env.DB.prepare("DELETE FROM customer_ticket_access WHERE expires_at <= ?").bind(now).run();
          await env.DB.prepare("INSERT INTO customer_ticket_access (token_hash, customer_id, expires_at, created_at) VALUES (?, ?, ?, ?)").bind(accessHash, user.id, now + 10 * 60 * 1000, now).run();
          response.ticketAccessToken = ticketAccessToken;
        }
        return json(response, 200, { "Set-Cookie": sessionCookie(token) });
      }

      if (path === "/api/customer/passenger-profiles" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "customer") return json({ success: false, message: "Customer sign-in is required." }, 403);
        const result = await env.DB.prepare(
          "SELECT full_name AS fullName, age, gender, from_station AS fromStation, to_station AS toStation, travel_class AS travelClass FROM customer_passenger_profiles WHERE customer_id = ? ORDER BY updated_at DESC"
        ).bind(user.id).all();
        return json({ success: true, profiles: result.results || [] });
      }

      if (path === "/api/customer/passenger-profiles" && method === "POST") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "customer") return json({ success: false, message: "Customer sign-in is required." }, 403);
        const body = await readJson(request);
        const profiles = Array.isArray(body.profiles) ? body.profiles.slice(0, 10) : [];
        let saved = 0;
        for (const item of profiles) {
          if (!item || typeof item !== "object") continue;
          const fullName = String(item.fullName || "").trim().slice(0, 100);
          if (!fullName) continue;
          const age = String(item.age || "").slice(0, 3);
          const gender = String(item.gender || "").slice(0, 20);
          const fromStation = String(item.fromStation || "").slice(0, 120);
          const toStation = String(item.toStation || "").slice(0, 120);
          const travelClass = String(item.travelClass || "").slice(0, 30);
          await env.DB.prepare(
            "DELETE FROM customer_passenger_profiles WHERE customer_id = ? AND full_name = ? COLLATE NOCASE"
          ).bind(user.id, fullName).run();
          await env.DB.prepare(
            "INSERT INTO customer_passenger_profiles (id, customer_id, full_name, age, gender, from_station, to_station, travel_class, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(crypto.randomUUID(), user.id, fullName, age, gender, fromStation, toStation, travelClass, now).run();
          saved++;
        }
        return json({ success: true, saved });
      }

      if (path === "/api/customer/passenger-profiles" && method === "DELETE") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "owner") return json({ success: false, message: "Only the Owner can clear saved customer filters." }, 403);
        const result = await env.DB.prepare("DELETE FROM customer_passenger_profiles").run();
        return json({ success: true, deleted: result.meta ? result.meta.changes || 0 : 0, message: "My ARTfive! Saved passenger filters were permanently cleared." });
      }

      if (path === "/api/requests" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to continue." }, 401);
        let result;
        if (user.role === "owner" || user.role === "staff") {
          result = await env.DB.prepare(
            `SELECT id, data, file_data, created_at, customer_id FROM requests ORDER BY created_at DESC`
          ).all();
        } else if (user.role === "customer") {
          result = await env.DB.prepare(
            `SELECT id, data, file_data, created_at, customer_id FROM requests WHERE customer_id = ? ORDER BY created_at DESC`
          ).bind(user.id).all();
        } else {
          return json({ success: false, message: "Access denied." }, 403);
        }
        return json({ success: true, requests: result.results || [] });
      }

      if (path === "/api/requests" && method === "POST") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "customer") return json({ success: false, message: "Customer sign-in is required to submit a ticket request." }, 401);
        const body = await readJson(request);
        const data = body.data && typeof body.data === "object" ? body.data : null;
        if (!data) return json({ success: false, message: "Ticket request details are missing." }, 400);
        data.customerId = user.id;
        data.customerName = user.name;
        data.customerPhone = user.phone;
        const id = crypto.randomUUID();
        const createdAt = now;
        const fileData = typeof body.file_data === "string" ? body.file_data : null;
        await env.DB.prepare(
          `INSERT INTO requests (id, data, file_data, created_at, customer_id) VALUES (?, ?, ?, ?, ?)`
        ).bind(id, JSON.stringify(data), fileData, createdAt, user.id).run();
        return json({ success: true, id, created_at: createdAt, customer_id: user.id }, 201);
      }

      if (path === "/api/requests" && method === "DELETE") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "owner") return json({ success: false, message: "Only the Owner can delete ticket requests." }, 403);
        const body = await readJson(request);
        const id = String(body.id || "").trim();
        if (!id) return json({ success: false, message: "Request ID is required." }, 400);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_payment_instructions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            option_no INTEGER NOT NULL CHECK (option_no IN (2, 3)),
            amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
            message TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE (request_id, option_no)
          )
        `).run();
        const ticketColumnsResult = await env.DB.prepare("PRAGMA table_info(tickets)").all();
        const ticketColumns = new Set((ticketColumnsResult.results || []).map(column => column.name));
        if (!ticketColumns.has("request_id")) await env.DB.prepare("ALTER TABLE tickets ADD COLUMN request_id TEXT").run();
        await env.DB.prepare("DELETE FROM tickets WHERE request_id = ?").bind(id).run();
        await env.DB.prepare("DELETE FROM customer_payment_instructions WHERE request_id = ?").bind(id).run();
        const result = await env.DB.prepare("DELETE FROM requests WHERE id = ?").bind(id).run();
        if (!result.meta || result.meta.changes === 0) return json({ success: false, message: "Ticket request was not found." }, 404);
        return json({ success: true, message: "Ticket request deleted." });
      }


      if (path === "/api/customers" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) {
          return json({ success: false, message: "Owner or Staff sign-in is required." }, 403);
        }
        const result = await env.DB.prepare(
          "SELECT id, name, phone FROM users WHERE role = 'customer' AND active = 1 ORDER BY name COLLATE NOCASE"
        ).all();
        return json({ success: true, customers: result.results || [] });
      }

      if (path === "/api/customer-payments" && (method === "GET" || method === "POST" || method === "DELETE")) {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to continue." }, 401);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_payment_instructions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            option_no INTEGER NOT NULL CHECK (option_no IN (2, 3)),
            amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
            message TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE (request_id, option_no)
          )
        `).run();
        await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_customer_payment_instructions_customer ON customer_payment_instructions(customer_id, option_no, updated_at DESC)").run();
        const paymentColumnsResult = await env.DB.prepare("PRAGMA table_info(customer_payment_instructions)").all();
        const paymentColumns = new Set((paymentColumnsResult.results || []).map(column => column.name));
        if (!paymentColumns.has("payment_status")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending'").run();
        if (!paymentColumns.has("verified_by")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_by TEXT").run();
        if (!paymentColumns.has("verified_at")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_at INTEGER").run();

        if (method === "GET") {
          let result;
          if (user.role === "customer") {
            result = await env.DB.prepare(
              "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt FROM customer_payment_instructions WHERE customer_id = ? ORDER BY updated_at DESC"
            ).bind(user.id).all();
          } else if (user.role === "owner" || user.role === "staff") {
            result = await env.DB.prepare(
              "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt FROM customer_payment_instructions ORDER BY updated_at DESC"
            ).all();
          } else return json({ success: false, message: "Access denied." }, 403);
          return json({ success: true, instructions: result.results || [] });
        }

        const body = await readJson(request);
        if (method === "POST" && body.action === "verify") {
          if (!["owner", "staff"].includes(user.role)) return json({ success: false, message: "Only the Owner or authorized Staff can verify customer payments." }, 403);
        } else if (user.role !== "owner") {
          return json({ success: false, message: "Only the Owner can manage customer payment instructions." }, 403);
        }
        const requestId = String(body.requestId || "").trim();
        if (!requestId) return json({ success: false, message: "Select the customer's ticket request." }, 400);
        const requestRow = await env.DB.prepare(
          "SELECT id, customer_id FROM requests WHERE id = ? LIMIT 1"
        ).bind(requestId).first();
        if (!requestRow) return json({ success: false, message: "The selected ticket request was not found." }, 404);

        if (body.action === "verify") {
          const optionNo = Number(body.optionNo);
          if (![2, 3].includes(optionNo)) return json({ success: false, message: "Choose Customer Option 2 or 3." }, 400);
          const instruction = await env.DB.prepare(
            "SELECT id, payment_status AS paymentStatus FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
          ).bind(requestId, optionNo).first();
          if (!instruction) return json({ success: false, message: "Send the payment amount and instructions before verifying payment." }, 404);
          if (optionNo === 3) {
            const bookingPayment = await env.DB.prepare(
              "SELECT payment_status FROM customer_payment_instructions WHERE request_id = ? AND option_no = 2 LIMIT 1"
            ).bind(requestId).first();
            if (!bookingPayment || bookingPayment.payment_status !== "verified") {
              return json({ success: false, message: "Verify Customer Option 2 booking-request payment before verifying Option 3." }, 409);
            }
          }
          const verifiedMessage = optionNo === 2
            ? "My ARTfive! have successfully received your Railway Ticket Booking Request Payment. Our team will now process your ticket booking."
            : "My ARTfive! have successfully received your ticket payment. Please visit: 🎫 Option 4 — GET MY TICKET! to collect and download your ticket after our team uploads it.";
          await env.DB.prepare(
            "UPDATE customer_payment_instructions SET payment_status = 'verified', verified_by = ?, verified_at = ?, message = ?, updated_at = ? WHERE request_id = ? AND option_no = ?"
          ).bind(user.id, now, verifiedMessage, now, requestId, optionNo).run();
          const verified = await env.DB.prepare(
            "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
          ).bind(requestId, optionNo).first();
          return json({ success: true, instruction: verified, message: "My ARTfive! Payment marked as manually verified." });
        }

        if (method === "DELETE") {
          const optionNo = Number(body.optionNo);
          if (![2, 3].includes(optionNo)) return json({ success: false, message: "Choose Customer Option 2 or 3." }, 400);
          const deleted = await env.DB.prepare(
            "DELETE FROM customer_payment_instructions WHERE request_id = ? AND option_no = ?"
          ).bind(requestId, optionNo).run();
          return json({ success: true, deleted: deleted.meta ? deleted.meta.changes || 0 : 0, message: "My ARTfive! Payment instructions were removed." });
        }

        const optionNo = Number(body.optionNo);
        if (optionNo === 3) {
          const bookingPayment = await env.DB.prepare(
            "SELECT payment_status FROM customer_payment_instructions WHERE request_id = ? AND option_no = 2 LIMIT 1"
          ).bind(requestId).first();
          if (!bookingPayment || bookingPayment.payment_status !== "verified") {
            return json({ success: false, message: "Complete and verify Customer Option 2 booking-request payment before sending Option 3 ticket charges." }, 409);
          }
        }
        const amount = Number(body.amount);
        const amountPaise = Math.round(amount * 100);
        let message = String(body.message || "").trim();
        if (![2, 3].includes(optionNo)) return json({ success: false, message: "Choose Customer Option 2 or 3." }, 400);
        if (!Number.isFinite(amount) || amount <= 0 || amountPaise > 100000000000) return json({ success: false, message: "Enter a valid payment amount." }, 400);
        if (!message) return json({ success: false, message: "Write a payment message before sending." }, 400);
        if (!/^My ARTfive!/i.test(message)) message = "My ARTfive! " + message;
        if (message.length > 2000) return json({ success: false, message: "The message is too long." }, 400);
        const id = crypto.randomUUID();
        await env.DB.prepare(`
          INSERT INTO customer_payment_instructions
            (id, request_id, customer_id, option_no, amount_paise, message, updated_by, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(request_id, option_no) DO UPDATE SET
            amount_paise = excluded.amount_paise,
            message = excluded.message,
            updated_by = excluded.updated_by,
            payment_status = 'pending',
            verified_by = NULL,
            verified_at = NULL,
            updated_at = excluded.updated_at
        `).bind(id, requestId, requestRow.customer_id, optionNo, amountPaise, message, user.id, now, now).run();
        const saved = await env.DB.prepare(
          "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
        ).bind(requestId, optionNo).first();
        return json({ success: true, instruction: saved, message: "My ARTfive! Payment amount and message were sent to the selected customer's dashboard option." }, 201);
      }

      if (path === "/api/tickets" && ["GET", "POST", "DELETE"].includes(method)) {
        const ticketColumnsResult = await env.DB.prepare("PRAGMA table_info(tickets)").all();
        const ticketColumns = new Set((ticketColumnsResult.results || []).map(column => column.name));
        if (!ticketColumns.has("request_id")) await env.DB.prepare("ALTER TABLE tickets ADD COLUMN request_id TEXT").run();
      }

      if (path === "/api/tickets" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to continue." }, 401);
        let result;
        if (user.role === "owner" || user.role === "staff") {
          result = await env.DB.prepare(
            "SELECT id, request_id AS requestId, customer_id AS customerId, customer_name AS customerName, customer_phone AS customerPhone, ticket_title AS ticketTitle, mime_type AS mimeType, file_data AS fileData, payment_confirmed AS paymentConfirmed, created_at AS createdAt FROM tickets ORDER BY created_at DESC"
          ).all();
        } else if (user.role === "customer") {
          const ticketAccessToken = request.headers.get("X-Ticket-Access") || "";
          if (!ticketAccessToken) return json({ success: false, message: "Please verify your phone number and password again to open GET MY TICKET!." }, 403);
          const ticketAccessHash = await sha256Base64(ticketAccessToken);
          const ticketAccess = await env.DB.prepare(
            "SELECT token_hash FROM customer_ticket_access WHERE token_hash = ? AND customer_id = ? AND expires_at > ? LIMIT 1"
          ).bind(ticketAccessHash, user.id, now).first();
          if (!ticketAccess) return json({ success: false, message: "Your ticket access verification has expired. Please sign in again." }, 403);
          result = await env.DB.prepare(
            "SELECT id, request_id AS requestId, customer_id AS customerId, customer_name AS customerName, customer_phone AS customerPhone, ticket_title AS ticketTitle, mime_type AS mimeType, file_data AS fileData, payment_confirmed AS paymentConfirmed, created_at AS createdAt FROM tickets WHERE customer_id = ? ORDER BY created_at DESC"
          ).bind(user.id).all();
        } else {
          return json({ success: false, message: "Access denied." }, 403);
        }
        return json({ success: true, tickets: result.results || [] });
      }

      if (path === "/api/tickets" && method === "POST") {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) {
          return json({ success: false, message: "Owner or Staff sign-in is required to send tickets." }, 403);
        }
        const body = await readJson(request);
        const customerId = String(body.customerId || "").trim();
        const requestId = String(body.requestId || "").trim();
        const ticketTitle = String(body.ticketTitle || "").trim();
        const fileData = String(body.fileData || "");
        if (!customerId || !requestId || !ticketTitle || !fileData) {
          return json({ success: false, message: "Select the customer's ticket request and ticket file before sending." }, 400);
        }
        if (ticketTitle.length > 180 || fileData.length > 1400000) {
          return json({ success: false, message: "Ticket file is too large. Please use a file smaller than about 1 MB." }, 413);
        }
        const match = fileData.match(/^data:(application\/pdf|application\/vnd\.openxmlformats-officedocument\.wordprocessingml\.document|application\/msword|image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
        if (!match) return json({ success: false, message: "Accepted ticket files: PDF, DOC, DOCX, PNG, JPEG or WEBP." }, 400);
        const customer = await env.DB.prepare(
          "SELECT id, name, phone FROM users WHERE id = ? AND role = 'customer' AND active = 1 LIMIT 1"
        ).bind(customerId).first();
        if (!customer) return json({ success: false, message: "The selected customer account was not found." }, 404);
        const requestRow = await env.DB.prepare(
          "SELECT id FROM requests WHERE id = ? AND customer_id = ? LIMIT 1"
        ).bind(requestId, customerId).first();
        if (!requestRow) return json({ success: false, message: "The selected request does not belong to this customer." }, 404);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_payment_instructions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            option_no INTEGER NOT NULL CHECK (option_no IN (2, 3)),
            amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
            message TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            payment_status TEXT NOT NULL DEFAULT 'pending',
            verified_by TEXT,
            verified_at INTEGER,
            UNIQUE (request_id, option_no)
          )
        `).run();
        const ticketPaymentColumnsResult = await env.DB.prepare("PRAGMA table_info(customer_payment_instructions)").all();
        const ticketPaymentColumns = new Set((ticketPaymentColumnsResult.results || []).map(column => column.name));
        if (!ticketPaymentColumns.has("payment_status")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'pending'").run();
        if (!ticketPaymentColumns.has("verified_by")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_by TEXT").run();
        if (!ticketPaymentColumns.has("verified_at")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN verified_at INTEGER").run();
        const collectionPayment = await env.DB.prepare(
          "SELECT id, payment_status FROM customer_payment_instructions WHERE request_id = ? AND customer_id = ? AND option_no = 3 LIMIT 1"
        ).bind(requestId, customerId).first();
        if (body.confirmOption3Payment !== true || !collectionPayment || collectionPayment.payment_status !== "verified") {
          return json({ success: false, message: "My ARTfive! Ticket upload is locked until the Owner or authorized Staff manually marks the Option 3 payment as received (✅)." }, 409);
        }
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO tickets (id, request_id, customer_id, customer_name, customer_phone, ticket_title, mime_type, file_data, payment_confirmed, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
        ).bind(id, requestId, customer.id, customer.name, customer.phone, ticketTitle, match[1], fileData, user.id, now).run();
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_notifications (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_id TEXT NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            read_at INTEGER
          )
        `).run();
        await env.DB.prepare(
          "INSERT INTO customer_notifications (id, customer_id, sender_id, message, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(
          crypto.randomUUID(),
          customer.id,
          user.id,
          "My ARTfive! have uploaded your railway ticket successfully. It is now available in 🎫 Option 4 — GET MY TICKET! Please sign in with the same phone number and password used when you created your customer account.",
          now
        ).run();
        return json({ success: true, id, message: "My ARTfive! Ticket uploaded and made available in Customer Option 4." }, 201);
      }

      if (path === "/api/tickets" && method === "DELETE") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "owner") {
          return json({ success: false, message: "Only the Owner can permanently delete ticket files." }, 403);
        }
        const body = await readJson(request);
        const id = String(body.id || "").trim();
        if (!id) return json({ success: false, message: "Ticket ID is required." }, 400);
        const ticket = await env.DB.prepare("SELECT id FROM tickets WHERE id = ? LIMIT 1").bind(id).first();
        if (!ticket) return json({ success: false, message: "Ticket was not found." }, 404);
        const deletion = await env.DB.prepare("DELETE FROM tickets WHERE id = ?").bind(id).run();
        if (!deletion.meta || deletion.meta.changes !== 1) return json({ success: false, message: "Ticket could not be permanently deleted." }, 500);
        return json({ success: true, message: "My ARTfive! Ticket file and its stored file data were permanently deleted from D1." });
      }

      return json({ success: false, message: "API endpoint not found." }, 404);
    } catch (error) {
      console.error("My ARTfive! API request failed:", {
        path,
        message: error && error.message ? error.message : String(error),
        stack: error && error.stack ? error.stack : null
      });
      if (error && error.message === "Request too large.") return json({ success: false, message: error.message }, 413);
      if (error && error.message === "Invalid JSON request.") return json({ success: false, message: error.message }, 400);
      return json({ success: false, message: "My ARTfive! Server could not complete this request. Please try again." }, 500);
    }
  }
};
