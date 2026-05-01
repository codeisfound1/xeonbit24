# 🪙 Xeonbit24 AI
 
> Blog phân tích tiền điện tử tự động — crawl từ RSS + Telegram, viết lại bởi AI Groq, deploy trên GitHub Pages.
 
---
 
## 🚀 Tính Năng
 
- **Tự động crawl** tin tức từ CoinDesk, Cointelegraph, Decrypt, The Block và kênh Telegram **@WatcherGuru**
- **AI phân tích** bằng Groq (Llama 3.3 70B) — dịch và viết lại thành bài tiếng Việt chuyên sâu
- **Dark theme** cao cấp với ticker giá crypto real-time
- **Price cards** hiển thị BTC, ETH, BNB, SOL, XRP, ADA
- **Quản trị nội tuyến** — sửa/xoá bài, batch commit lên GitHub
- **SEO tốt** — Schema.org, sitemap.xml, robots.txt, og:image
- **Cloudinary** upload ảnh tự động (tuỳ chọn)
- **Deploy miễn phí** trên GitHub Pages
---
 
## ⚙️ Cài Đặt
 
### 1. Fork repo này
 
```bash
git clone https://github.com/YOUR_USERNAME/xeonbit24
cd xeonbit24
```
 
### 2. Tạo GitHub Secrets
 
Vào **Settings → Secrets and variables → Actions** và thêm:
 
| Secret | Mô tả | Bắt buộc |
|--------|-------|----------|
| `GROQ_API_KEY` | API key từ [console.groq.com](https://console.groq.com) | ✅ |
| `SITE_URL` | URL GitHub Pages của bạn (VD: `https://username.github.io/xeonbit24`) | ✅ |
| `CLOUDINARY_CLOUD_NAME` | Tên cloud Cloudinary | ❌ |
| `CLOUDINARY_API_KEY` | API key Cloudinary | ❌ |
| `CLOUDINARY_API_SECRET` | API secret Cloudinary | ❌ |
| `TELEGRAM_BOT_TOKEN` | Bot token — để gửi bài lên nhóm Telegram của bạn | ❌ |
| `TELEGRAM_CHAT_ID` | Chat ID nhóm/kênh nhận bài | ❌ |
 
> **Không cần** `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, hay `TELEGRAM_SESSION`.  
> Tin từ @WatcherGuru được đọc qua RSS public — không cần xác thực.
 
### 3. Bật GitHub Pages
 
**Settings → Pages → Source → Deploy from branch → main → /docs**
 
### 4. Chạy thử
 
Vào **Actions → 🤖 Tạo bài crypto tự động → Run workflow**
 
---
 
## 📰 Nguồn Dữ Liệu
 
| # | Nguồn | Loại | Ghi chú |
|---|-------|------|---------|
| 1 | [CoinDesk](https://www.coindesk.com/arc/outboundfeeds/rss/) | RSS | Weight 3 |
| 2 | [Cointelegraph](https://cointelegraph.com/rss) | RSS | Weight 3 |
| 3 | [Decrypt](https://decrypt.co/feed) | RSS | Weight 2 |
| 4 | [The Block](https://www.theblock.co/rss.xml) | RSS | Weight 2 |
| 5 | [@WatcherGuru](https://t.me/WatcherGuru) | Telegram | 3 tin mới nhất |
 
### Cách lấy tin từ @WatcherGuru
 
Kênh `@WatcherGuru` là kênh **public** — script đọc qua RSS do [RSSHub](https://rsshub.app) cung cấp:
 
```
https://rsshub.app/telegram/channel/WatcherGuru
```
 
**Không cần** cài thêm package, không cần tài khoản Telegram, không cần xác thực.  
Script tự động gọi URL này và parse 3 tin mới nhất, merge vào pool cùng các RSS feed khác trước khi đưa vào Groq tổng hợp.
 
---
 
## 📁 Cấu Trúc
 
```
xeonbit24/
├── docs/
│   ├── index.html      # Trang web chính (dark crypto theme)
│   ├── posts.json      # Dữ liệu bài viết
│   ├── sitemap.xml     # SEO sitemap
│   └── robots.txt      # SEO robots
├── scripts/
│   ├── generate.js     # Script crawl + AI generate
│   └── package.json
└── .github/workflows/
    └── generate.yml    # GitHub Actions (chạy 2 lần/ngày)
```
 
---
 
## 🕐 Lịch Chạy Tự Động
 
- **7:00 sáng** (UTC+7) — crawl bài mới buổi sáng
- **19:00 tối** (UTC+7) — crawl bài mới buổi tối
---
 
## 🔧 Chạy Thủ Công
 
Từ giao diện web, nhấn **⚡ Đăng bài mới** và điền thông tin GitHub.
 
Hoặc từ terminal:
```bash
export GROQ_API_KEY=your_key
node scripts/generate.js
```
 
---
 
## ⚠️ Disclaimer
 
Nội dung chỉ mang tính tham khảo, không phải lời khuyên đầu tư tài chính.
