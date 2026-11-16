
const PASSWORD_ITERATIONS = 100000;
const SESSION_DAYS = 7;
const MAX_BODY_BYTES = 3 * 1024 * 1024;
const SESSION_COOKIE = "artfive_session";

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

    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

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
        return json({ success: true, message: "My ARTfive! Manager security verified." });
      }

      if (path === "/api/owner/login" && method === "POST") {
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
        const body = await readJson(request);
        const name = String(body.name || "").trim();
        const phone = String(body.phone || "").trim();
        const password = String(body.password || "");
        if (!name || !phone || password.length < 8) return json({ success: false, message: "Enter your name, phone number and a password of at least 8 characters." }, 400);
        if (name.length > 100 || phone.length > 30) return json({ success: false, message: "Some details are too long." }, 400);
        const existing = await env.DB.prepare("SELECT id FROM users WHERE phone = ? LIMIT 1").bind(phone).first();
        if (existing) return json({ success: false, message: "This phone number is already registered. Please sign in." }, 409);
        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(
          `INSERT INTO users (id, name, email, phone, role, password_hash, active, created_at)
           VALUES (?, ?, NULL, ?, 'customer', ?, 1, ?)`
        ).bind(id, name, phone, passwordHash, now).run();
        return json({ success: true, message: "My ARTfive! Customer account created successfully." }, 201);
      }

      if (path === "/api/customer/login" && method === "POST") {
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
        return json({ success: true, user: publicUser(user) }, 200, { "Set-Cookie": sessionCookie(token) });
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

      if (path === "/api/tickets" && method === "GET") {
        const user = await getSessionUser(request, env, now);
        if (!user) return json({ success: false, message: "Please sign in to continue." }, 401);
        let result;
        if (user.role === "owner" || user.role === "staff") {
          result = await env.DB.prepare(
            "SELECT id, customer_id AS customerId, customer_name AS customerName, customer_phone AS customerPhone, ticket_title AS ticketTitle, mime_type AS mimeType, file_data AS fileData, payment_confirmed AS paymentConfirmed, created_at AS createdAt FROM tickets ORDER BY created_at DESC"
          ).all();
        } else if (user.role === "customer") {
          result = await env.DB.prepare(
            "SELECT id, customer_id AS customerId, customer_name AS customerName, customer_phone AS customerPhone, ticket_title AS ticketTitle, mime_type AS mimeType, file_data AS fileData, payment_confirmed AS paymentConfirmed, created_at AS createdAt FROM tickets WHERE customer_id = ? ORDER BY created_at DESC"
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
        const ticketTitle = String(body.ticketTitle || "").trim();
        const fileData = String(body.fileData || "");
        if (!customerId || !ticketTitle || !fileData || body.paymentConfirmed !== true) {
          return json({ success: false, message: "Select a customer, ticket file and confirm collection payment before sending." }, 400);
        }
        if (ticketTitle.length > 180 || fileData.length > 1400000) {
          return json({ success: false, message: "Ticket file is too large. Please use a file smaller than about 1 MB." }, 413);
        }
        const match = fileData.match(/^data:(application\/pdf|image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/);
        if (!match) return json({ success: false, message: "Only PDF, PNG, JPEG or WEBP ticket files are accepted." }, 400);
        const customer = await env.DB.prepare(
          "SELECT id, name, phone FROM users WHERE id = ? AND role = 'customer' AND active = 1 LIMIT 1"
        ).bind(customerId).first();
        if (!customer) return json({ success: false, message: "The selected customer account was not found." }, 404);
        const id = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO tickets (id, customer_id, customer_name, customer_phone, ticket_title, mime_type, file_data, payment_confirmed, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
        ).bind(id, customer.id, customer.name, customer.phone, ticketTitle, match[1], fileData, user.id, now).run();
        return json({ success: true, id, message: "My ARTfive! Ticket sent successfully." }, 201);
      }

      if (path === "/api/tickets" && method === "DELETE") {
        const user = await getSessionUser(request, env, now);
        if (!user || user.role !== "owner") {
          return json({ success: false, message: "Only the Owner can permanently delete ticket files." }, 403);
        }
        const body = await readJson(request);
        const id = String(body.id || "").trim();
        if (!id) return json({ success: false, message: "Ticket ID is required." }, 400);
        const result = await env.DB.prepare("DELETE FROM tickets WHERE id = ?").bind(id).run();
        if (!result.meta || result.meta.changes === 0) return json({ success: false, message: "Ticket was not found." }, 404);
        return json({ success: true, message: "Ticket file and its database record were permanently deleted." });
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
