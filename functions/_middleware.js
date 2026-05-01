// ── Cloudflare Pages Middleware ──────────────────────────────────────────────
// Đặt file này tại: functions/_middleware.js (gốc repo, KHÔNG trong docs/)
// Bảo vệ /admin.html bằng HTTP Basic Authentication
// Cấu hình trong Cloudflare Pages → Settings → Environment variables:
//   ADMIN_USER = tên đăng nhập của bạn
//   ADMIN_PASS = mật khẩu mạnh của bạn

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);

  // Chỉ bảo vệ đường dẫn /admin (và /admin.html, /admin/*)
  if (!url.pathname.startsWith('/admin')) {
    return next();
  }

  const ADMIN_USER = env.ADMIN_USER ;
  const ADMIN_PASS = env.ADMIN_PASS ;

  const authHeader = request.headers.get('Authorization');

  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const encoded = authHeader.slice(6);
      const decoded = atob(encoded);
      const colonIndex = decoded.indexOf(':');
      if (colonIndex !== -1) {
        const user = decoded.slice(0, colonIndex);
        const pass = decoded.slice(colonIndex + 1);
        if (user === ADMIN_USER && pass === ADMIN_PASS) {
          return next(); // ✅ Đúng thông tin → cho vào
        }
      }
    } catch (e) {
      // Lỗi decode → từ chối
    }
  }

  // ❌ Chưa đăng nhập hoặc sai → trả 401, browser hiện popup
  return new Response('Unauthorized — Vui lòng đăng nhập để tiếp tục.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Crypto Insight Admin", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}
