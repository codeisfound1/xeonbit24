// docs/worker.js  — Cloudflare Workers entry point
// Bảo vệ /admin.html bằng HTTP Basic Auth
// Set env vars trong Cloudflare Dashboard:
//   ADMIN_USER = tên đăng nhập
//   ADMIN_PASS = mật khẩu

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Chỉ chặn /admin và /admin.html
    if (url.pathname === '/admin' || url.pathname === '/admin.html' || url.pathname.startsWith('/admin/')) {
      const authHeader = request.headers.get('Authorization');

      if (authHeader && authHeader.startsWith('Basic ')) {
        try {
          const decoded = atob(authHeader.slice(6));
          const colonIndex = decoded.indexOf(':');
          if (colonIndex !== -1) {
            const user = decoded.slice(0, colonIndex);
            const pass = decoded.slice(colonIndex + 1);
            if (user === env.ADMIN_USER && pass === env.ADMIN_PASS) {
              // ✅ Auth đúng → serve file tĩnh bình thường
              return env.ASSETS.fetch(request);
            }
          }
        } catch (e) {
          // Lỗi decode → từ chối
        }
      }

      // ❌ Chưa đăng nhập hoặc sai → trả 401
      return new Response('Unauthorized — Vui lòng đăng nhập để tiếp tục.', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="Xeonbit24 Admin", charset="UTF-8"',
          'Content-Type': 'text/plain; charset=utf-8',
        },
      });
    }

    // Các route khác → serve file tĩnh bình thường
    return env.ASSETS.fetch(request);
  },
};
