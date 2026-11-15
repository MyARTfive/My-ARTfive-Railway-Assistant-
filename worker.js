
const json = (data, status = 200) =>
  Response.json(data, { status });

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$310000$${toBase64(salt)}$${toBase64(new Uint8Array(bits))}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const now = Date.now();
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1").run();
        return json({
          success: true,
          message: "My ARTfive! Worker and D1 are connected."
        });
      } catch {
        return json(
          { success: false, message: "Database connection failed." },
          503
        );
      }
    }

    if (url.pathname.startsWith("/api/")) {
      try {
        if (ip !== "unknown") {
          const blocked = await env.DB.prepare(
            `SELECT ip_address FROM blocked_ips
             WHERE ip_address = ?
             AND (blocked_until IS NULL OR blocked_until > ?)`
          ).bind(ip, now).first();

          if (blocked) {
            await env.DB.prepare(
              `INSERT INTO security_logs
               (ip_address, event_type, details, created_at)
               VALUES (?, ?, ?, ?)`
            ).bind(ip, "blocked_request", "Request rejected by IP block list", now).run();

            return json({ success: false, message: "Access denied." }, 403);
          }
        }
      } catch {
        return json({ success: false, message: "Security check unavailable." }, 503);
      }

      // Protected first-owner setup
      if (url.pathname === "/api/owner/setup" && request.method === "POST") {
        try {
          if (!env.OWNER_SETUP_KEY) {
            return json({ success: false, message: "Owner setup is not configured." }, 503);
          }

          const contentLength = Number(request.headers.get("Content-Length") || 0);
          if (contentLength > 10000) {
            return json({ success: false, message: "Request too large." }, 413);
          }

          const body = await request.json();

          if (!safeEqual(body.setupKey, env.OWNER_SETUP_KEY)) {
            await env.DB.prepare(
              `INSERT INTO security_logs
               (ip_address, event_type, details, created_at)
               VALUES (?, ?, ?, ?)`
            ).bind(ip, "owner_setup_denied", "Invalid owner setup key", now).run();

            return json({ success: false, message: "Invalid setup key." }, 403);
          }

          const existingOwner = await env.DB.prepare(
            "SELECT id FROM users WHERE role = 'owner' LIMIT 1"
          ).first();

          if (existingOwner) {
            return json({ success: false, message: "An owner account already exists." }, 409);
          }

          const name = String(body.name || "").trim();
          const email = String(body.email || "").trim().toLowerCase();
          const phone = String(body.phone || "").trim();
          const password = String(body.password || "");

          if (!name || !email || !password || password.length < 12) {
            return json({
              success: false,
              message: "Enter your name, email and a password of at least 12 characters."
            }, 400);
          }

          if (name.length > 100 || email.length > 254 || phone.length > 30) {
            return json({ success: false, message: "Some details are too long." }, 400);
          }

          const passwordHash = await hashPassword(password);
          const id = crypto.randomUUID();

          await env.DB.prepare(
            `INSERT INTO users
             (id, name, email, phone, role, password_hash, active, created_at)
             VALUES (?, ?, ?, ?, 'owner', ?, 1, ?)`
          ).bind(
            id,
            name,
            email,
            phone || null,
            passwordHash,
            now
          ).run();

          await env.DB.prepare(
            `INSERT INTO security_logs
             (ip_address, event_type, details, created_at)
             VALUES (?, ?, ?, ?)`
          ).bind(ip, "owner_setup_success", "Owner account created", now).run();

          return json({
            success: true,
            message: "Owner account created securely. Please sign in."
          }, 201);

        } catch (error) {
          return json({ success: false, message: "Owner setup failed. Check the details and try again." }, 400);
        }
      }

      return json({ success: false, message: "API endpoint not enabled yet." }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};
