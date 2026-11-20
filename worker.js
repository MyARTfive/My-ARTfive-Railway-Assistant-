// Backend redeploy trigger: Option 2 verification is not required to send Option 3 notifications.

const PASSWORD_ITERATIONS = 100000;
const SESSION_DAYS = 7;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const SESSION_COOKIE = "artfive_session";
const MANAGER_SESSION_COOKIE = "artfive_manager_session";

const json = (data, status = 200, headers = {}) => {
  const responseHeaders = new Headers(headers);
  // Authenticated account data must never be stored in browser or intermediary HTTP caches.
  responseHeaders.set("Cache-Control", "no-store, private, max-age=0");
  responseHeaders.set("Pragma", "no-cache");
  return Response.json(data, { status, headers: responseHeaders });
};

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

async function ensureTicketNotificationColumns(env) {
  const result = await env.DB.prepare("PRAGMA table_info(customer_notifications)").all();
  const columns = new Set((result.results || []).map(column => column.name));
  if (!columns.has("ticket_id")) await env.DB.prepare("ALTER TABLE customer_notifications ADD COLUMN ticket_id TEXT").run();
  if (!columns.has("target_option")) await env.DB.prepare("ALTER TABLE customer_notifications ADD COLUMN target_option INTEGER").run();
  if (!columns.has("expires_at")) await env.DB.prepare("ALTER TABLE customer_notifications ADD COLUMN expires_at INTEGER").run();
  // Existing ticket-upload notices receive the same 15-minute lifetime as new notices.
  await env.DB.prepare("UPDATE customer_notifications SET expires_at = created_at + 900000 WHERE ticket_id IS NOT NULL AND target_option IN (3, 4) AND expires_at IS NULL").run();
}

async function ensureStaffNotificationSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS staff_notifications (
      id TEXT PRIMARY KEY,
      staff_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      created_at INTEGER NOT NULL,
      read_at INTEGER
    )
  `).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_staff_notifications_staff_created ON staff_notifications(staff_id, created_at DESC)").run();
}

async function addStaffNotification(env, staffId, title, message, category, now) {
  await ensureStaffNotificationSchema(env);
  const safeMessage = /^My ARTfive!/i.test(message) ? message : "My ARTfive! " + message;
  await env.DB.prepare(
    "INSERT INTO staff_notifications (id, staff_id, title, message, category, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(crypto.randomUUID(), staffId, String(title || "My ARTfive! Notification").slice(0, 120), safeMessage.slice(0, 2000), String(category || "general").slice(0, 40), now).run();
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

async function ensureStaffChatSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS staff_chat_messages (
      id TEXT PRIMARY KEY,
      staff_id TEXT,
      sender_id TEXT NOT NULL REFERENCES users(id),
      sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff')),
      sender_name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `).run();
  const info = await env.DB.prepare("PRAGMA table_info(staff_chat_messages)").all();
  const columns = new Set((info.results || []).map(column => column.name));
  if (!columns.has("staff_id")) await env.DB.prepare("ALTER TABLE staff_chat_messages ADD COLUMN staff_id TEXT").run();
  // Legacy Staff messages belong to their sender. Old Owner messages had no recipient,
  // so they are intentionally not exposed in any private Staff conversation.
  await env.DB.prepare("UPDATE staff_chat_messages SET staff_id = sender_id WHERE sender_role = 'staff' AND staff_id IS NULL").run();
  // Normalize historical sender labels as well as labels on newly sent messages.
  await env.DB.prepare("UPDATE staff_chat_messages SET sender_name = 'My ARTfive!' WHERE sender_role = 'owner' AND sender_name <> 'My ARTfive!'").run();
  await env.DB.prepare("UPDATE staff_chat_messages SET sender_name = COALESCE((SELECT name FROM users WHERE users.id = staff_chat_messages.sender_id), 'Staff') WHERE sender_role = 'staff'").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_staff_chat_messages_staff_created ON staff_chat_messages(staff_id, created_at)").run();
}

async function purgeExpiredChatMessages(env, now = Date.now()) {
  const cutoff = now - 24 * 60 * 60 * 1000;
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS customer_enquiry_messages (
      id TEXT PRIMARY KEY,
      request_id TEXT,
      customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sender_id TEXT NOT NULL REFERENCES users(id),
      sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff','customer')),
      sender_name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `).run();
  // Link an optional enquiry submitted with a ticket request to that exact request.
  // Existing chat history is preserved when this column is added.
  const enquiryColumns = await env.DB.prepare("PRAGMA table_info(customer_enquiry_messages)").all();
  if (!(enquiryColumns.results || []).some(column => column.name === "request_id")) {
    await env.DB.prepare("ALTER TABLE customer_enquiry_messages ADD COLUMN request_id TEXT").run();
  }
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_customer_enquiry_request ON customer_enquiry_messages(request_id)").run();
  await ensureStaffChatSchema(env);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM staff_chat_messages WHERE created_at <= ?").bind(cutoff),
    env.DB.prepare("DELETE FROM customer_enquiry_messages WHERE created_at <= ?").bind(cutoff)
  ]);
}

export default {
  async scheduled(controller, env, ctx) {
    await purgeExpiredChatMessages(env, Date.now());
  },
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

      if (path === "/api/owner/services" && (method === "GET" || method === "POST")) {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the signed-in Owner can manage services." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS app_services (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            icon TEXT NOT NULL DEFAULT 'fa-solid fa-layer-group',
            display_order INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('active','inactive','draft')),
            created_by TEXT NOT NULL REFERENCES users(id),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const result = await env.DB.prepare(
            "SELECT id, slug, name, description, icon, display_order AS displayOrder, status, created_at AS createdAt, updated_at AS updatedAt FROM app_services ORDER BY display_order ASC, created_at ASC"
          ).all();
          return json({ success: true, services: result.results || [] });
        }
        const body = await readJson(request);
        const action = String(body.action || "create");
        if (action === "create") {
          const name = String(body.name || "").trim().slice(0, 80);
          const description = String(body.description || "").trim().slice(0, 300);
          const icon = String(body.icon || "fa-solid fa-layer-group").trim().slice(0, 80);
          const displayOrder = Number.isInteger(Number(body.displayOrder)) ? Math.max(0, Math.min(9999, Number(body.displayOrder))) : 0;
          const status = ["active", "inactive", "draft"].includes(body.status) ? body.status : "draft";
          if (!name) return json({ success: false, message: "Enter a service name." }, 400);
          const slug = name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "service";
          const id = crypto.randomUUID();
          try {
            await env.DB.prepare(
              "INSERT INTO app_services (id, slug, name, description, icon, display_order, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(id, slug + "-" + id.slice(0, 8), name, description, icon, displayOrder, status, owner.id, now, now).run();
          } catch (error) {
            console.error("My ARTfive! Service create failed:", error.message);
            return json({ success: false, message: "The service could not be saved. Please try again." }, 500);
          }
          return json({ success: true, id, message: "My ARTfive! Service created successfully." }, 201);
        }
        if (action === "update" || action === "status") {
          const id = String(body.id || "").trim();
          if (!id) return json({ success: false, message: "Select a service first." }, 400);
          const existing = await env.DB.prepare("SELECT id FROM app_services WHERE id = ? LIMIT 1").bind(id).first();
          if (!existing) return json({ success: false, message: "Service was not found." }, 404);
          if (action === "status") {
            const status = String(body.status || "");
            if (!["active", "inactive", "draft"].includes(status)) return json({ success: false, message: "Choose a valid service status." }, 400);
            await env.DB.prepare("UPDATE app_services SET status = ?, updated_at = ? WHERE id = ?").bind(status, now, id).run();
          } else {
            const name = String(body.name || "").trim().slice(0, 80);
            const description = String(body.description || "").trim().slice(0, 300);
            const icon = String(body.icon || "fa-solid fa-layer-group").trim().slice(0, 80);
            const displayOrder = Number.isInteger(Number(body.displayOrder)) ? Math.max(0, Math.min(9999, Number(body.displayOrder))) : 0;
            const status = String(body.status || "");
            if (!name) return json({ success: false, message: "Enter a service name." }, 400);
            if (!["active", "inactive", "draft"].includes(status)) return json({ success: false, message: "Choose a valid service status." }, 400);
            await env.DB.prepare(
              "UPDATE app_services SET name = ?, description = ?, icon = ?, display_order = ?, status = ?, updated_at = ? WHERE id = ?"
            ).bind(name, description, icon, displayOrder, status, now, id).run();
          }
          return json({ success: true, message: "My ARTfive! Service updated successfully." });
        }
        return json({ success: false, message: "Unsupported service action." }, 400);
      }

      if (path === "/api/owner/assistant/github-status" && method === "GET") {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the signed-in Owner can inspect the GitHub project." }, 403);
        const repository = "MyARTfive/My-ARTfive-Railway-Assistant-";
        const branch = "feature/one-app-integration";
        const headers = {
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "My-ARTfive-Railway-Assistant"
        };
        try {
          const endpoints = [
            fetch("https://api.github.com/repos/" + repository, { headers }),
            fetch("https://api.github.com/repos/" + repository + "/branches/" + encodeURIComponent(branch), { headers }),
            fetch("https://api.github.com/repos/" + repository + "/commits?sha=" + encodeURIComponent(branch) + "&per_page=5", { headers }),
            fetch("https://api.github.com/repos/" + repository + "/actions/runs?branch=" + encodeURIComponent(branch) + "&per_page=5", { headers })
          ];
          const [repoResponse, branchResponse, commitsResponse, runsResponse] = await Promise.all(endpoints);
          if (!repoResponse.ok || !branchResponse.ok || !commitsResponse.ok) {
            const response = [repoResponse, branchResponse, commitsResponse].find(item => !item.ok);
            const status = response?.status || 502;
            return json({ success: false, message: status === 404
              ? "My ARTfive! GitHub could not find this public repository or branch. Check repository visibility and branch name."
              : status === 403
                ? "My ARTfive! GitHub rate limit or access restriction reached. Please wait and try again."
                : "My ARTfive! GitHub status is temporarily unavailable. Please try again later." }, status === 404 ? 404 : status === 403 ? 429 : 502);
          }
          const [repoData, branchData, commitsData] = await Promise.all([
            repoResponse.json(), branchResponse.json(), commitsResponse.json()
          ]);
          let workflowRuns = [];
          if (runsResponse.ok) {
            const runsData = await runsResponse.json();
            workflowRuns = (runsData.workflow_runs || []).slice(0, 5).map(run => ({
              id: run.id,
              name: String(run.name || "GitHub Actions").slice(0, 120),
              status: String(run.status || "unknown"),
              conclusion: run.conclusion ? String(run.conclusion) : "",
              url: String(run.html_url || "")
            }));
          }
          const commits = (Array.isArray(commitsData) ? commitsData : []).map(commit => ({
            sha: String(commit.sha || "").slice(0, 7),
            message: String(commit.commit?.message || "Commit").split("\n")[0].slice(0, 180),
            date: String(commit.commit?.author?.date || "").slice(0, 10)
          }));
          return json({
            success: true,
            status: {
              repository: String(repoData.full_name || repository),
              visibility: repoData.private ? "Private repository" : "Public repository",
              branch,
              latestCommit: String(branchData.commit?.sha || "").slice(0, 7),
              commits,
              workflowRuns
            }
          });
        } catch (error) {
          console.error("My ARTfive! GitHub assistant status failed:", error?.message || error);
          return json({ success: false, message: "My ARTfive! Could not reach GitHub. Check your connection and try again." }, 502);
        }
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

      if (path === "/api/owner/control/customer-accounts" && method === "GET") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required to view registered accounts." }, 403);
        const result = await env.DB.prepare(
          "SELECT id, name, phone, role, created_at AS createdAt, active FROM users WHERE role IN ('customer', 'staff') ORDER BY created_at DESC, role, name COLLATE NOCASE"
        ).all();
        return json({ success: true, customers: result.results || [] });
      }

      if (path === "/api/owner/control/customer-accounts/status" && method === "POST") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required to change account access." }, 403);
        const body = await readJson(request);
        const accountId = String(body.accountId || "").trim();
        const action = String(body.action || "").trim().toLowerCase();
        const reason = String(body.reason || "").trim().slice(0, 250);
        if (!accountId || !["block", "unblock"].includes(action)) return json({ success: false, message: "Select a registered account and choose Block or Unblock." }, 400);
        const account = await env.DB.prepare("SELECT id, name, phone, role, active FROM users WHERE id = ? AND role IN ('customer','staff') LIMIT 1").bind(accountId).first();
        if (!account) return json({ success: false, message: "Only registered Customer or Staff accounts can be blocked or unblocked." }, 404);
        const active = action === "unblock" ? 1 : 0;
        if (Number(account.active) === active) return json({ success: true, active, message: action === "block" ? "My ARTfive! This account is already blocked." : "My ARTfive! This account is already active." });
        await env.DB.prepare("UPDATE users SET active = ? WHERE id = ? AND role IN ('customer','staff')").bind(active, accountId).run();
        if (action === "block") {
          await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(accountId).run();
          try { await env.DB.prepare("DELETE FROM customer_ticket_access WHERE customer_id = ?").bind(accountId).run(); } catch {}
        }
        const notificationMessage = action === "block"
          ? "My ARTfive! Sign-in to your account has been temporarily blocked by the Owner. Contact My ARTfive! if you believe this is a mistake."
          : "My ARTfive! Your account access has been restored by the Owner. You can sign in again.";
        if (account.role === "staff") {
          await addStaffNotification(env, accountId, action === "block" ? "My ARTfive! Account access blocked" : "My ARTfive! Account access restored", notificationMessage, "security", now);
        } else {
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
          await env.DB.prepare("INSERT INTO customer_notifications (id, customer_id, sender_id, message, created_at) VALUES (?, ?, ?, ?, ?)").bind(crypto.randomUUID(), accountId, owner.id, notificationMessage, now).run();
        }
        await logSecurity(env, ip, "account_" + action + "ed", "Owner " + action + "ed " + account.role + " account " + accountId + (reason ? "; reason: " + reason : ""), now);
        return json({ success: true, active, message: action === "block" ? "My ARTfive! Account sign-in blocked. Existing sessions were revoked." : "My ARTfive! Account sign-in restored. The account can sign in again." });
      }

      if (path === "/api/owner/control/customer-accounts/delete" && method === "POST") {
        const owner = await getManagerVerifiedOwner(request, env, now);
        if (!owner) return json({ success: false, message: "Owner sign-in and Manager verification are required to delete registered accounts." }, 403);
        const body = await readJson(request);
        const customerId = String(body.accountId || body.customerId || "").trim();
        if (!customerId) return json({ success: false, message: "Select a Customer ID or Staff ID to delete." }, 400);
        const customer = await env.DB.prepare(
          "SELECT id, name, phone, role FROM users WHERE id = ? AND role IN ('customer', 'staff') LIMIT 1"
        ).bind(customerId).first();
        if (!customer) return json({ success: false, message: "The selected account was not found. Refresh the list and try again." }, 404);

        // Ensure the private Staff conversation recipient column exists before account cleanup.
        await ensureStaffChatSchema(env);
        // Delete only records belonging to this selected customer or staff account. Keep owner accounts, shared settings, visitor/security logs, and unrelated accounts untouched.
        const tableResult = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).all();
        const tables = new Set((tableResult.results || []).map(row => row.name));
        const cleanup = [
          ["tickets", "customer_id = ?", [customerId]],
          ["requests", "customer_id = ?", [customerId]],
          ["customer_enquiry_messages", "customer_id = ? OR sender_id = ?", [customerId, customerId]],
          ["staff_chat_messages", "sender_id = ? OR staff_id = ?", [customerId, customerId]],
          ["customer_notifications", "customer_id = ?", [customerId]],
          ["staff_notifications", "staff_id = ?", [customerId]],
          ["customer_payment_instructions", "customer_id = ?", [customerId]],
          ["ticket_payment_verifications", "customer_id = ?", [customerId]],
          ["customer_ticket_access", "customer_id = ?", [customerId]],
          ["customer_passenger_profiles", "customer_id = ?", [customerId]],
          ["customer_engagement", "customer_id = ?", [customerId]],
          ["password_change_requests", "user_id = ?", [customerId]],
          ["manager_sessions", "owner_id = ?", [customerId]],
          ["sessions", "user_id = ?", [customerId]]
        ];
        const statements = cleanup
          .filter(([table]) => tables.has(table))
          .map(([table, where, values]) => env.DB.prepare("DELETE FROM " + table + " WHERE " + where).bind(...values));
        if (customer.role === "staff" && tables.has("staff_signup_requests")) {
          statements.push(env.DB.prepare("DELETE FROM staff_signup_requests WHERE phone = ?").bind(customer.phone));
        }

        // Preserve customer-facing records when a staff account is deleted by transferring
        // uploader/sender/creator references to the verified Owner before removing the account.
        if (tables.has("tickets")) {
          statements.push(env.DB.prepare("UPDATE tickets SET uploaded_by = ? WHERE uploaded_by = ?").bind(owner.id, customerId));
        }
        if (tables.has("customer_notifications")) {
          statements.push(env.DB.prepare("UPDATE customer_notifications SET sender_id = ? WHERE sender_id = ?").bind(owner.id, customerId));
        }
        if (tables.has("app_updates")) {
          statements.push(env.DB.prepare("UPDATE app_updates SET created_by = ? WHERE created_by = ?").bind(owner.id, customerId));
        }

        statements.push(
          env.DB.prepare("DELETE FROM users WHERE id = ? AND role IN ('customer', 'staff')").bind(customerId)
        );
        const results = await env.DB.batch(statements);
        const deletedAccount = results[results.length - 1];
        if (!Number(deletedAccount?.meta?.changes || 0)) {
          return json({ success: false, message: "The selected account could not be deleted. Refresh and try again." }, 409);
        }
        await logSecurity(env, ip, "account_id_deleted", "Owner permanently deleted registered account " + customerId, now);
        return json({
          success: true,
          customerId,
          message: "My ARTfive! The selected account was permanently deleted from D1. The person may register again later."
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
        await purgeExpiredChatMessages(env, now);
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
        // The sender name is displayed separately in the chat UI, so store only
        // the message body and avoid repeating the My ARTfive! prefix in the text.
        const finalMessage = user.role === "customer" ? messageText : messageText.replace(/^My ARTfive!\s*/i, "");
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO customer_enquiry_messages (id, customer_id, sender_id, sender_role, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, targetCustomerId, user.id, user.role, senderName, finalMessage, now).run();
        return json({ success: true, id, message: "My ARTfive! Enquiry message saved." }, 201);
      }

      if (path === "/api/owner/staff-ticket-assignment" && (method === "GET" || method === "POST")) {
        const owner = await getSessionUser(request, env, now);
        if (!owner || !["owner", "staff"].includes(owner.role)) return json({ success: false, message: "Owner or Staff sign-in is required." }, 403);
        if (method === "POST" && owner.role !== "owner") return json({ success: false, message: "Only the Owner can change Staff ticket assignment permission." }, 403);
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
        if (method === "POST") {
          const body = await readJson(request);
          const enabled = body.enabled === true;
          await env.DB.prepare("INSERT INTO app_settings (setting_key, setting_json, updated_by, updated_at) VALUES ('staff_ticket_assignment_enabled', ?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_json = excluded.setting_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at")
            .bind(JSON.stringify(enabled), owner.id, now).run();
          return json({ success: true, enabled });
        }
        const row = await env.DB.prepare("SELECT setting_json FROM app_settings WHERE setting_key = 'staff_ticket_assignment_enabled' LIMIT 1").first();
        let enabled = false;
        try { enabled = row ? JSON.parse(row.setting_json) === true : false; } catch {}
        return json({ success: true, enabled });
      }

      if (path === "/api/owner/staff-payment-tick" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) return json({ success: false, message: "Owner or Staff sign-in is required." }, 403);
        if (method === "POST" && user.role !== "owner") return json({ success: false, message: "Only the Owner can change Staff payment tick visibility." }, 403);
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
        if (method === "POST") {
          const body = await readJson(request);
          const enabled = body.enabled === true;
          await env.DB.prepare("INSERT INTO app_settings (setting_key, setting_json, updated_by, updated_at) VALUES ('staff_payment_tick_enabled', ?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_json = excluded.setting_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at")
            .bind(JSON.stringify(enabled), user.id, now).run();
          return json({ success: true, enabled });
        }
        const row = await env.DB.prepare("SELECT setting_json FROM app_settings WHERE setting_key = 'staff_payment_tick_enabled' LIMIT 1").first();
        let enabled = false;
        try { enabled = row ? JSON.parse(row.setting_json) === true : false; } catch {}
        return json({ success: true, enabled });
      }

      if (path === "/api/staff-chat/recipients" && method === "GET") {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Only the Owner can view Staff chat recipients." }, 403);
        const rows = await env.DB.prepare(
          "SELECT id, name, phone FROM users WHERE role = 'staff' AND active = 1 ORDER BY name COLLATE NOCASE"
        ).all();
        return json({ success: true, staff: rows.results || [] });
      }

      if (path === "/api/staff-chat" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) return json({ success: false, message: "Only Owner and Staff can access Staff Chat." }, 403);
        await ensureStaffChatSchema(env);
        await purgeExpiredChatMessages(env, now);
        if (method === "GET") {
          let staffId = user.id;
          if (user.role === "owner") {
            staffId = String(url.searchParams.get("staffId") || "").trim();
            if (!staffId) return json({ success: true, messages: [] });
            const target = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND role = 'staff' AND active = 1 LIMIT 1").bind(staffId).first();
            if (!target) return json({ success: false, message: "The selected Staff account was not found." }, 404);
          }
          const rows = await env.DB.prepare(
            "SELECT id, sender_role AS senderRole, sender_name AS sender, message AS text, created_at AS createdAt FROM staff_chat_messages WHERE staff_id = ? ORDER BY created_at ASC LIMIT 300"
          ).bind(staffId).all();
          return json({ success: true, messages: rows.results || [] });
        }
        const body = await readJson(request);
        const messageText = String(body.message || "").trim();
        if (!messageText || messageText.length > 2000) return json({ success: false, message: "Enter a message up to 2,000 characters." }, 400);
        let staffId = user.id;
        if (user.role === "owner") {
          staffId = String(body.staffId || "").trim();
          if (!staffId) return json({ success: false, message: "Select the exact Staff member before sending a message." }, 400);
          const target = await env.DB.prepare("SELECT id FROM users WHERE id = ? AND role = 'staff' AND active = 1 LIMIT 1").bind(staffId).first();
          if (!target) return json({ success: false, message: "The selected Staff account was not found." }, 404);
        }
        const senderName = user.role === "owner" ? "My ARTfive!" : String(user.name || "Staff");
        const finalMessage = messageText;
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO staff_chat_messages (id, staff_id, sender_id, sender_role, sender_name, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, staffId, user.id, user.role, senderName, finalMessage, now).run();
        return json({ success: true, id, message: "My ARTfive! Private Staff message saved." }, 201);
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
        await ensureTicketNotificationColumns(env);
        if (method === "GET") {
          await env.DB.prepare("DELETE FROM customer_notifications WHERE expires_at IS NOT NULL AND expires_at <= ?").bind(now).run();
          if (user.role === "customer") {
            const rows = await env.DB.prepare(
              "SELECT n.id, n.message, n.created_at AS createdAt, n.read_at AS readAt, n.target_option AS targetOption, n.ticket_id AS ticketId, n.expires_at AS expiresAt, CASE WHEN sender.role = 'owner' THEN 'My ARTfive!' ELSE COALESCE(sender.name, 'Staff') END AS senderName FROM customer_notifications n LEFT JOIN users sender ON sender.id = n.sender_id WHERE n.customer_id = ? AND (n.expires_at IS NULL OR n.expires_at > ?) ORDER BY n.created_at DESC LIMIT 100"
            ).bind(user.id, now).all();
            return json({ success: true, notifications: rows.results || [] });
          }
          if (user.role === "owner") {
            const rows = await env.DB.prepare(
              "SELECT n.id, n.customer_id AS customerId, u.name AS customerName, u.phone AS customerPhone, n.message, n.created_at AS createdAt, n.read_at AS readAt, n.target_option AS targetOption, n.ticket_id AS ticketId, n.expires_at AS expiresAt FROM customer_notifications n JOIN users u ON u.id = n.customer_id WHERE n.expires_at IS NULL OR n.expires_at > ? ORDER BY n.created_at DESC LIMIT 300"
            ).bind(now).all();
            return json({ success: true, notifications: rows.results || [] });
          }
          return json({ success: false, message: "Access denied." }, 403);
        }
        if (user.role !== "owner") return json({ success: false, message: "Only the Owner can send customer notifications." }, 403);
        const body = await readJson(request);
        let message = String(body.message || "").trim();
        const customerId = String(body.accountId || body.customerId || "").trim();
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

      if (path === "/api/staff/notifications" && (method === "GET" || method === "POST")) {
        const staff = await getSessionUser(request, env, now);
        if (!staff || staff.role !== "staff") return json({ success: false, message: "Staff sign-in is required to view Staff notifications." }, 403);
        await ensureStaffNotificationSchema(env);
        if (method === "GET") {
          const rows = await env.DB.prepare(
            "SELECT id, title, message, category, created_at AS createdAt, read_at AS readAt FROM staff_notifications WHERE staff_id = ? ORDER BY created_at DESC LIMIT 100"
          ).bind(staff.id).all();
          return json({ success: true, notifications: rows.results || [] });
        }
        const body = await readJson(request);
        const notificationId = String(body.notificationId || "").trim();
        if (!notificationId) return json({ success: false, message: "Select a Staff notification to mark as read." }, 400);
        const result = await env.DB.prepare(
          "UPDATE staff_notifications SET read_at = COALESCE(read_at, ?) WHERE id = ? AND staff_id = ?"
        ).bind(now, notificationId, staff.id).run();
        if (!Number(result.meta?.changes || 0)) return json({ success: false, message: "This Staff notification was not found." }, 404);
        return json({ success: true, message: "My ARTfive! Staff notification marked as read." });
      }

      if (path === "/api/staff/signup-status" && method === "GET") {
        const requestId = String(url.searchParams.get("requestId") || "").trim();
        if (!/^[0-9a-f-]{36}$/i.test(requestId)) return json({ success: false, message: "A valid Staff signup request reference is required." }, 400);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS staff_signup_requests (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, password_hash TEXT,
            status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
            created_at INTEGER NOT NULL, reviewed_at INTEGER
          )
        `).run();
        const signup = await env.DB.prepare("SELECT status FROM staff_signup_requests WHERE id = ? LIMIT 1").bind(requestId).first();
        if (!signup) return json({ success: false, message: "Staff signup request was not found." }, 404);
        const status = String(signup.status || "pending");
        const message = status === "approved"
          ? "My ARTfive! Your Staff account has been approved. You can now sign in."
          : status === "rejected"
            ? "My ARTfive! Your Staff signup request was rejected. Please contact My ARTfive! for assistance."
            : "My ARTfive! Your Staff signup request is waiting for Owner approval.";
        return json({ success: true, status, message });
      }

      if (path === "/api/staff/signup" && method === "POST") {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS staff_signup_requests (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT,
            status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER
          )
        `).run();
        if (await loginRateLimited(env, ip, "staff_signup_attempt", now)) return json({ success: false, message: "Too many Staff registration attempts from this connection. Please wait 15 minutes and try again." }, 429);
        await logSecurity(env, ip, "staff_signup_attempt", "Staff signup request submitted", now);
        const body = await readJson(request);
        const name = String(body.name || "").trim();
        const phone = String(body.phone || "").trim();
        const password = String(body.password || "");
        if (!name || !phone || password.length < 8 || name.length > 100 || phone.length > 30) return json({ success: false, message: "Please enter your full name and phone number, and create a password with at least 8 characters." }, 400);
        const existingUser = await env.DB.prepare("SELECT id FROM users WHERE phone = ? LIMIT 1").bind(phone).first();
        const pending = await env.DB.prepare("SELECT id FROM staff_signup_requests WHERE phone = ? AND status = 'pending' LIMIT 1").bind(phone).first();
        if (existingUser || pending) return json({ success: false, message: "This phone number is already registered or has a Staff request waiting for approval. Please sign in or contact My ARTfive!." }, 409);
        const passwordHash = await hashPassword(password);
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO staff_signup_requests (id, name, phone, password_hash, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)").bind(id, name, phone, passwordHash, now).run();
        return json({ success: true, requestId: id, status: "pending", message: "My ARTfive! Staff registration request submitted for Owner approval." }, 201);
      }

      if (path === "/api/owner/staff-signup-requests" && (method === "GET" || method === "POST")) {
        const owner = await getSessionUser(request, env, now);
        if (!owner || owner.role !== "owner") return json({ success: false, message: "Owner sign-in is required." }, 403);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS staff_signup_requests (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT,
            status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
            created_at INTEGER NOT NULL,
            reviewed_at INTEGER
          )
        `).run();
        if (method === "GET") {
          const rows = await env.DB.prepare("SELECT id, name, phone, status, created_at AS createdAt FROM staff_signup_requests WHERE status = 'pending' ORDER BY created_at ASC").all();
          return json({ success: true, requests: rows.results || [] });
        }
        const body = await readJson(request);
        const requestId = String(body.requestId || "").trim();
        const decision = String(body.decision || "").trim().toLowerCase();
        if (!requestId || !["approve","reject"].includes(decision)) return json({ success: false, message: "Invalid staff approval action." }, 400);
        const signup = await env.DB.prepare("SELECT id, name, phone, password_hash, status FROM staff_signup_requests WHERE id = ? LIMIT 1").bind(requestId).first();
        if (!signup || signup.status !== "pending") return json({ success: false, message: "This staff request is no longer pending. Refresh the list." }, 409);
        if (decision === "approve") {
          const existingUser = await env.DB.prepare("SELECT id FROM users WHERE phone = ? LIMIT 1").bind(signup.phone).first();
          if (existingUser) return json({ success: false, message: "This phone number is already registered." }, 409);
          const staffId = crypto.randomUUID();
          await ensureStaffNotificationSchema(env);
          const notificationId = crypto.randomUUID();
          await env.DB.batch([
            env.DB.prepare("INSERT INTO users (id, name, email, phone, role, password_hash, active, created_at) VALUES (?, ?, NULL, ?, 'staff', ?, 1, ?)").bind(staffId, signup.name, signup.phone, signup.password_hash, now),
            env.DB.prepare("UPDATE staff_signup_requests SET status = 'approved', password_hash = NULL, reviewed_at = ? WHERE id = ? AND status = 'pending'").bind(now, requestId),
            env.DB.prepare("INSERT INTO staff_notifications (id, staff_id, title, message, category, created_at) VALUES (?, ?, ?, ?, 'account', ?)").bind(
              notificationId,
              staffId,
              "My ARTfive! Staff account approved",
              "My ARTfive! Your Staff account has been approved. You can now sign in to your Staff Dashboard.",
              now
            )
          ]);
        } else {
          await env.DB.prepare("UPDATE staff_signup_requests SET status = 'rejected', password_hash = NULL, reviewed_at = ? WHERE id = ? AND status = 'pending'").bind(now, requestId).run();
        }
        return json({ success: true, message: decision === "approve" ? "My ARTfive! Staff account approved successfully. A notification is waiting in the Staff Dashboard." : "My ARTfive! Staff signup request rejected. The applicant can check the decision using their signup reference." });
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
        if (!user) {
          await env.DB.prepare(`CREATE TABLE IF NOT EXISTS staff_signup_requests (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, password_hash TEXT, status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')), created_at INTEGER NOT NULL, reviewed_at INTEGER)`).run();
          const rejected = await env.DB.prepare("SELECT id FROM staff_signup_requests WHERE phone = ? AND status = 'rejected' ORDER BY reviewed_at DESC LIMIT 1").bind(identifier).first();
          if (rejected) return json({ success: false, message: "Error!" }, 401);
        }
        if (user && user.active !== 1) {
          await logSecurity(env, ip, "staff_owner_login_blocked", "Blocked Staff sign-in attempt", now);
          return json({ success: false, message: "Error!" }, 401);
        }
        if (!user || !(await verifyPassword(password, user.password_hash))) {
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
        if (user && user.active !== 1) {
          await logSecurity(env, ip, "customer_login_blocked", "Blocked customer sign-in attempt", now);
          return json({ success: false, message: "Error!" }, 401);
        }
        if (!user || !(await verifyPassword(password, user.password_hash))) {
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
        const enquiryText = String(data.enquiry || "").trim().slice(0, 2000);
        if (enquiryText) await purgeExpiredChatMessages(env, now);
        const statements = [
          env.DB.prepare(
            `INSERT INTO requests (id, data, file_data, created_at, customer_id) VALUES (?, ?, ?, ?, ?)`
          ).bind(id, JSON.stringify(data), fileData, createdAt, user.id)
        ];
        // The optional Customer Option 1 enquiry is also placed in the same
        // customer conversation shown in the customer form and Owner Chat 1.
        // Keep it linked so deleting this request removes only this request's
        // enquiry message, without touching other conversation messages.
        if (enquiryText) {
          statements.push(env.DB.prepare(
            "INSERT INTO customer_enquiry_messages (id, request_id, customer_id, sender_id, sender_role, sender_name, message, created_at) VALUES (?, ?, ?, ?, 'customer', ?, ?, ?)"
          ).bind(crypto.randomUUID(), id, user.id, user.id, user.name, enquiryText, createdAt));
        }
        await env.DB.batch(statements);
        return json({ success: true, id, created_at: createdAt, customer_id: user.id }, 201);
      }

      if (path === "/api/requests" && method === "DELETE") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "owner") return json({ success: false, message: "Only the Owner can delete ticket requests." }, 403);
        const body = await readJson(request);
        const id = String(body.id || "").trim();
        if (!id) return json({ success: false, message: "Request ID is required." }, 400);
        // Option 8 permanently deletes the selected request from D1. Its linked
        // optional enquiry is removed from the Customer Option 1 / Owner Chat 1
        // conversation too. Other chat messages, payment instructions and tickets
        // are deliberately preserved.
        await purgeExpiredChatMessages(env, now);
        const requestRow = await env.DB.prepare("SELECT id, customer_id FROM requests WHERE id = ? LIMIT 1").bind(id).first();
        if (!requestRow) return json({ success: false, message: "Ticket request was not found." }, 404);
        const deleted = await env.DB.batch([
          env.DB.prepare("DELETE FROM customer_enquiry_messages WHERE request_id = ? AND customer_id = ?").bind(id, requestRow.customer_id),
          env.DB.prepare("DELETE FROM requests WHERE id = ? AND customer_id = ?").bind(id, requestRow.customer_id)
        ]);
        const deletedRequestCount = deleted[1]?.meta ? Number(deleted[1].meta.changes || 0) : 0;
        if (deletedRequestCount === 0) return json({ success: false, message: "Ticket request was not found." }, 404);
        return json({ success: true, message: "Ticket request and its linked enquiry were permanently deleted from D1. Other messages, payment instructions and uploaded tickets remain unchanged." });
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
        if (!paymentColumns.has("is_active")) await env.DB.prepare("ALTER TABLE customer_payment_instructions ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1").run();

        if (method === "GET") {
          let result;
          if (user.role === "customer") {
            result = await env.DB.prepare(
              "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt, is_active AS isActive FROM customer_payment_instructions WHERE customer_id = ? AND is_active = 1 ORDER BY updated_at DESC"
            ).bind(user.id).all();
          } else if (user.role === "owner" || user.role === "staff") {
            result = await env.DB.prepare(
              "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt, is_active AS isActive FROM customer_payment_instructions ORDER BY updated_at DESC"
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
        const selectedCustomerId = String(body.customerId || "").trim();
        if (user.role === "owner" && !selectedCustomerId && body.action !== "verify") return json({ success: false, message: "My ARTfive! Select the exact customer ID before sending or unsending a notification." }, 400);
        if (selectedCustomerId && selectedCustomerId !== String(requestRow.customer_id)) {
          return json({ success: false, message: "My ARTfive! The selected ticket request does not belong to the selected customer. Please choose that customer's request and send again." }, 400);
        }

        if (body.action === "unsend") {
          const optionNo = Number(body.optionNo);
          const instructionId = String(body.instructionId || "").trim();
          const amount = Number(body.amount);
          const amountPaise = Math.round(amount * 100);
          const message = String(body.message || "").trim();
          if (![2, 3].includes(optionNo)) return json({ success: false, message: "Choose Customer Option 2 or 3." }, 400);
          if (!instructionId || !Number.isFinite(amount) || amount <= 0 || !message) {
            return json({ success: false, message: "My ARTfive! Select the exact sent notification and enter its amount before unsending." }, 400);
          }
          const deleted = await env.DB.prepare(
            "DELETE FROM customer_payment_instructions WHERE id = ? AND request_id = ? AND option_no = ? AND customer_id = ? AND amount_paise = ? AND message = ?"
          ).bind(instructionId, requestId, optionNo, requestRow.customer_id, amountPaise, message).run();
          const deletedCount = deleted.meta ? Number(deleted.meta.changes || 0) : 0;
          if (deletedCount < 1) {
            return json({ success: false, deleted: 0, message: "My ARTfive! The selected notification, customer, option or amount did not match the saved D1 record. Nothing was deleted." }, 409);
          }
          return json({ success: true, deleted: deletedCount, message: "My ARTfive! The selected notification and amount have been permanently deleted from D1 and the customer dashboard. Your UPI number and QR code remain unchanged." });
        }

        if (body.action === "verify") {
          const optionNo = Number(body.optionNo);
          if (![2, 3].includes(optionNo)) return json({ success: false, message: "Choose Customer Option 2 or 3." }, 400);
          const instruction = await env.DB.prepare(
            "SELECT id, payment_status AS paymentStatus FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
          ).bind(requestId, optionNo).first();
          if (!instruction) return json({ success: false, message: "Send the payment amount and instructions before verifying payment." }, 404);
          const verifiedMessage = optionNo === 2
            ? "My ARTfive! have successfully received your Railway Ticket Booking Request Payment. Our team will now process your ticket booking."
            : "My ARTfive! have successfully received your ticket payment. Please visit: 🎫 Option 4 — GET MY TICKET! to collect and download your ticket after our team uploads it.";
          await env.DB.prepare(
            "UPDATE customer_payment_instructions SET payment_status = 'verified', verified_by = ?, verified_at = ?, message = ?, updated_at = ? WHERE request_id = ? AND option_no = ?"
          ).bind(user.id, now, verifiedMessage, now, requestId, optionNo).run();
          const verified = await env.DB.prepare(
            "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt, is_active AS isActive FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
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
            customer_id = excluded.customer_id,
            amount_paise = excluded.amount_paise,
            message = excluded.message,
            updated_by = excluded.updated_by,
            payment_status = 'pending',
            verified_by = NULL,
            verified_at = NULL,
            is_active = 1,
            updated_at = excluded.updated_at
        `).bind(id, requestId, requestRow.customer_id, optionNo, amountPaise, message, user.id, now, now).run();
        const saved = await env.DB.prepare(
          "SELECT id, request_id AS requestId, customer_id AS customerId, option_no AS optionNo, amount_paise AS amountPaise, message, payment_status AS paymentStatus, verified_at AS verifiedAt, updated_at AS updatedAt FROM customer_payment_instructions WHERE request_id = ? AND option_no = ? LIMIT 1"
        ).bind(requestId, optionNo).first();
        return json({ success: true, instruction: saved, message: "My ARTfive! Payment amount and message were sent to the selected customer's dashboard option." }, 201);
      }

      if (path === "/api/ticket-payment-verification" && (method === "GET" || method === "POST")) {
        const user = await getSessionUser(request, env, now);
        if (!user || !["owner", "staff"].includes(user.role)) {
          return json({ success: false, message: "Owner or Staff sign-in is required." }, 403);
        }
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS ticket_payment_verifications (
            request_id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            verified_by TEXT NOT NULL,
            verified_at INTEGER NOT NULL
          )
        `).run();
        if (method === "GET") {
          const result = await env.DB.prepare(
            "SELECT request_id AS requestId, customer_id AS customerId, 1 AS verified, verified_by AS verifiedBy, verified_at AS verifiedAt FROM ticket_payment_verifications"
          ).all();
          return json({ success: true, verifications: result.results || [] });
        }
        if (user.role !== "owner") return json({ success: false, message: "Only the Owner can confirm ticket collection payment." }, 403);
        const body = await readJson(request);
        const customerId = String(body.accountId || body.customerId || "").trim();
        const requestId = String(body.requestId || "").trim();
        if (!customerId || !requestId) return json({ success: false, message: "Select the customer and exact ticket request." }, 400);
        const requestRow = await env.DB.prepare(
          "SELECT id FROM requests WHERE id = ? AND customer_id = ? LIMIT 1"
        ).bind(requestId, customerId).first();
        if (!requestRow) return json({ success: false, message: "The selected ticket request does not belong to this customer." }, 404);
        await env.DB.prepare(
          "INSERT INTO ticket_payment_verifications (request_id, customer_id, verified_by, verified_at) VALUES (?, ?, ?, ?) ON CONFLICT(request_id) DO UPDATE SET customer_id = excluded.customer_id, verified_by = excluded.verified_by, verified_at = excluded.verified_at"
        ).bind(requestId, customerId, user.id, now).run();
        return json({ success: true, message: "My ARTfive! Payment confirmation saved. Ticket upload is now unlocked." });
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
            "SELECT tickets.id, tickets.request_id AS requestId, tickets.customer_id AS customerId, tickets.customer_name AS customerName, tickets.customer_phone AS customerPhone, tickets.ticket_title AS ticketTitle, tickets.mime_type AS mimeType, tickets.file_data AS fileData, tickets.payment_confirmed AS paymentConfirmed, tickets.uploaded_by AS uploadedBy, uploader.role AS uploadedByRole, uploader.name AS uploadedByName, tickets.created_at AS createdAt FROM tickets LEFT JOIN users uploader ON uploader.id = tickets.uploaded_by ORDER BY tickets.created_at DESC"
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
            "SELECT tickets.id, tickets.request_id AS requestId, tickets.customer_id AS customerId, tickets.customer_name AS customerName, tickets.customer_phone AS customerPhone, tickets.ticket_title AS ticketTitle, tickets.mime_type AS mimeType, tickets.file_data AS fileData, tickets.payment_confirmed AS paymentConfirmed, tickets.uploaded_by AS uploadedBy, uploader.role AS uploadedByRole, uploader.name AS uploadedByName, tickets.created_at AS createdAt FROM tickets LEFT JOIN users uploader ON uploader.id = tickets.uploaded_by WHERE tickets.customer_id = ? ORDER BY tickets.created_at DESC"
          ).bind(user.id).all();
        } else {
          return json({ success: false, message: "Access denied." }, 403);
        }
        return json({ success: true, tickets: result.results || [] });
      }

      if (path === "/api/tickets" && method === "POST") {
        const user = await getSessionUser(request, env, now);
        if (user && user.role === "staff") {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
          const permission = await env.DB.prepare("SELECT setting_json FROM app_settings WHERE setting_key = 'staff_ticket_assignment_enabled' LIMIT 1").first();
          let enabled = false;
          try { enabled = permission ? JSON.parse(permission.setting_json) === true : false; } catch {}
          if (!enabled) return json({ success: false, message: "My ARTfive! Staff ticket assignment is currently OFF. Please contact the Owner." }, 403);
        }
        if (!user || !["owner", "staff"].includes(user.role)) {
          return json({ success: false, message: "Owner or Staff sign-in is required to send tickets." }, 403);
        }
        const body = await readJson(request);
        const customerId = String(body.accountId || body.customerId || "").trim();
        const requestId = String(body.requestId || "").trim();
        const ticketTitle = String(body.ticketTitle || "").trim();
        const fileData = String(body.fileData || "");
        if (!customerId || !requestId || !ticketTitle || !fileData) {
          return json({ success: false, message: "Select the customer's ticket request and ticket file before sending." }, 400);
        }
        if (ticketTitle.length > 180 || fileData.length > 1400000) {
          return json({ success: false, message: "Ticket file is too large. Please use a file smaller than about 1 MB." }, 413);
        }
        const match = fileData.match(/^data:(application\/pdf|image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
        if (!match) return json({ success: false, message: "Accepted ticket files: PDF, PNG, JPEG or WEBP." }, 400);
        const customer = await env.DB.prepare(
          "SELECT id, name, phone FROM users WHERE id = ? AND role = 'customer' AND active = 1 LIMIT 1"
        ).bind(customerId).first();
        if (!customer) return json({ success: false, message: "The selected customer account was not found." }, 404);
        const requestRow = await env.DB.prepare(
          "SELECT id FROM requests WHERE id = ? AND customer_id = ? LIMIT 1"
        ).bind(requestId, customerId).first();
        if (!requestRow) return json({ success: false, message: "The selected request does not belong to this customer." }, 404);
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS ticket_payment_verifications (
            request_id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            verified_by TEXT NOT NULL,
            verified_at INTEGER NOT NULL
          )
        `).run();
        const paymentConfirmation = await env.DB.prepare(
          "SELECT request_id FROM ticket_payment_verifications WHERE request_id = ? AND customer_id = ? LIMIT 1"
        ).bind(requestId, customerId).first();
        if (!paymentConfirmation) {
          return json({ success: false, message: "My ARTfive! Ticket upload is locked until the Owner manually marks the payment received (✅)." }, 409);
        }
        const id = crypto.randomUUID();
        // Notification creation is part of the successful ticket-send transaction.
        // If any insert fails, the ticket and its payment-confirmation consumption roll back too.
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
        await ensureTicketNotificationColumns(env);
        const ticketMessages = [
          {
            targetOption: 3,
            message: "My ARTfive! have uploaded your railway ticket successfully. It is now available in customer dashboard 🎫 Option 4 — GET MY TICKET! Please sign in with the same phone number and password used when you created your customer account."
          },
          {
            targetOption: 4,
            message: "My ARTfive! Thank you for choosing us! Your confirmed railway ticket is ready. You can now view and download your ticket. You're always most welcome to visit us again. Have a safe and happy journey! ❤️"
          }
        ];
        // Both automatic ticket-upload notifications expire 15 minutes after the ticket is sent.
        const notificationExpiry = now + 15 * 60 * 1000;
        // Keep the saved Owner payment confirmation. A successful send resets only
        // the two dashboard switches; it never deletes ticket_payment_verifications.
        await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_settings (setting_key TEXT PRIMARY KEY, setting_json TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL)").run();
        const sendResults = await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO tickets (id, request_id, customer_id, customer_name, customer_phone, ticket_title, mime_type, file_data, payment_confirmed, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
          ).bind(id, requestId, customer.id, customer.name, customer.phone, ticketTitle, match[1], fileData, user.id, now),
          ...ticketMessages.map(ticketMessage => env.DB.prepare(
            "INSERT INTO customer_notifications (id, customer_id, sender_id, message, created_at, ticket_id, target_option, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(crypto.randomUUID(), customer.id, user.id, ticketMessage.message, now, id, ticketMessage.targetOption, notificationExpiry)),
          env.DB.prepare(
            "INSERT INTO app_settings (setting_key, setting_json, updated_by, updated_at) VALUES ('staff_payment_tick_enabled', 'false', ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_json = 'false', updated_by = excluded.updated_by, updated_at = excluded.updated_at"
          ).bind(user.id, now),
          env.DB.prepare(
            "INSERT INTO app_settings (setting_key, setting_json, updated_by, updated_at) VALUES ('staff_ticket_assignment_enabled', 'false', ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_json = 'false', updated_by = excluded.updated_by, updated_at = excluded.updated_at"
          ).bind(user.id, now)
        ]);
        if (!sendResults[0]?.meta || sendResults[0].meta.changes !== 1 ||
            !sendResults[1]?.meta || sendResults[1].meta.changes !== 1 ||
            !sendResults[2]?.meta || sendResults[2].meta.changes !== 1) {
          return json({ success: false, message: "My ARTfive! Ticket and notifications could not be saved together. Please try again." }, 500);
        }
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
        await ensureTicketNotificationColumns(env);
        const deleteResults = await env.DB.batch([
          env.DB.prepare("DELETE FROM customer_notifications WHERE ticket_id = ?").bind(id),
          env.DB.prepare("DELETE FROM tickets WHERE id = ?").bind(id)
        ]);
        const deletion = deleteResults[1];
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
