
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const now = Date.now();
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    // Public health check
    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1").run();

        return Response.json({
          success: true,
          message: "My ARTfive! Worker and D1 are connected."
        });
      } catch (error) {
        return Response.json(
          { success: false, message: "Database connection failed." },
          { status: 503 }
        );
      }
    }

    // Protect API routes using the blocked IP list
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
            ).bind(
              ip,
              "blocked_request",
              "Request rejected by IP block list",
              now
            ).run();

            return Response.json(
              { success: false, message: "Access denied." },
              { status: 403 }
            );
          }
        }
      } catch (error) {
        return Response.json(
          { success: false, message: "Security check unavailable." },
          { status: 503 }
        );
      }

      // Other API routes will be enabled after authentication is connected.
      return Response.json(
        { success: false, message: "API endpoint not enabled yet." },
        { status: 404 }
      );
    }

    // Serve the existing app and PWA files
    return env.ASSETS.fetch(request);
  }
};
