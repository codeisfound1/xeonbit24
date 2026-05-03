// scripts/generate.js
// Sources: Public RSS from CoinDesk, Cointelegraph, Decrypt, The Block
// Fetch Top 10 latest news → Groq AI summarizes → saves docs/posts.json

"use strict";

const https  = require("https");
const http   = require("http");
const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");

// ─── CONFIG ────────────────────────────────────────────────────────────────

// Public RSS feeds — no API key required, not blocked by robots
const RSS_SOURCES = [
  //{ name: "WatcherGuru",   url: "https://watcher.guru/news/feed",                       weight: 5 },
  { name: "CoinDesk",      url: "https://www.coindesk.com/arc/outboundfeeds/rss/",       weight: 3 },
  { name: "Cointelegraph", url: "https://cointelegraph.com/rss",                         weight: 2 },
  { name: "Decrypt",       url: "https://decrypt.co/feed",                               weight: 2 },
  { name: "The Block",     url: "https://www.theblock.co/rss.xml",                       weight: 2 },
];

const TOP_N = 10;  // Số tin tổng hợp mỗi lần chạy

const GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "llama-3.3-70b-versatile";

const POSTS_FILE   = path.join(__dirname, "../docs/posts.json");
const SITEMAP_FILE = path.join(__dirname, "../docs/sitemap.xml");
const ROBOTS_FILE  = path.join(__dirname, "../docs/robots.txt");
const SITE_URL     = process.env.SITE_URL || "https://xeonbit24.com";
const GROQ_KEY     = process.env.GROQ_API_KEY;
const FORCE        = process.env.FORCE === "true";

// Cloudinary (tuỳ chọn)
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY    = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// Telegram (tuỳ chọn) — dùng bot token của admin để gửi vào nhóm
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// Telegram — đọc kênh public @WatcherGuru qua RSS (không cần MTProto/session)
const WATCHER_GURU_CHANNEL = process.env.WATCHER_GURU_CHANNEL; //"WatcherGuru";
const WATCHER_GURU_LIMIT   = process.env.WATCHER_GURU_LIMIT;//3; // Số tin mới nhất cần lấy

if (!GROQ_KEY) {
  console.error("❌ Missing GROQ_API_KEY");
  process.exit(1);
}

// ─── HTTP HELPERS ──────────────────────────────────────────────────────────

/**
 * Blocks URLs that could be used for Server-Side Request Forgery (SSRF):
 *  - Non-HTTP/HTTPS schemes (file://, ftp://, gopher://, etc.)
 *  - Private IPv4 ranges: loopback, link-local, RFC-1918, CGNAT
 *  - IPv6 loopback / unspecified
 *  - Common cloud-metadata endpoints (169.254.169.254 AWS/GCP/Azure,
 *    100.100.100.200 Alibaba, fd00:ec2::254 AWS IPv6)
 *
 * Throws a plain Error so callers can surface it without crashing the process.
 */
function assertSafeUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    throw new Error("SSRF block: invalid URL — " + raw);
  }

  // Scheme must be http or https
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("SSRF block: disallowed scheme '" + parsed.protocol + "' in " + raw);
  }

  const host = parsed.hostname.toLowerCase();

  // Strip IPv6 brackets: [::1] → ::1
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;

  // Blocked hostnames / exact addresses
  const BLOCKED_HOSTS = new Set([
    "localhost",
    "metadata.google.internal",   // GCP metadata
    "169.254.169.254",            // AWS / Azure / GCP link-local metadata
    "100.100.100.200",            // Alibaba Cloud metadata
  ]);
  if (BLOCKED_HOSTS.has(bare)) {
    throw new Error("SSRF block: blocked host '" + bare + "' in " + raw);
  }

  // Blocked IPv6 addresses
  const BLOCKED_IPV6 = new Set(["::1", "::", "0:0:0:0:0:0:0:1", "fd00:ec2::254"]);
  if (BLOCKED_IPV6.has(bare)) {
    throw new Error("SSRF block: blocked IPv6 '" + bare + "' in " + raw);
  }

  // Private / reserved IPv4 CIDR ranges checked via numeric comparison.
  // Covers: 127.x, 10.x, 172.16–31.x, 192.168.x, 169.254.x (link-local),
  //         100.64–127.x (CGNAT), 0.x (this-network), 192.0.2/198.51.100/203.0.113 (documentation).
  const ipv4Re = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const m = bare.match(ipv4Re);
  if (m) {
    const [, a, b, c] = m.map(Number);
    const blocked =
      a === 0                                   || // 0.0.0.0/8
      a === 10                                  || // 10.0.0.0/8
      a === 127                                 || // 127.0.0.0/8 loopback
      (a === 100 && b >= 64 && b <= 127)        || // 100.64.0.0/10 CGNAT
      (a === 169 && b === 254)                  || // 169.254.0.0/16 link-local
      (a === 172 && b >= 16 && b <= 31)         || // 172.16.0.0/12 RFC-1918
      (a === 192 && b === 0  && c === 2)        || // 192.0.2.0/24 documentation
      (a === 192 && b === 168)                  || // 192.168.0.0/16 RFC-1918
      (a === 198 && b === 18)                   || // 198.18.0.0/15 benchmarking
      (a === 198 && b === 51  && c === 100)     || // 198.51.100.0/24 documentation
      (a === 203 && b === 0   && c === 113)     || // 203.0.113.0/24 documentation
      a >= 224;                                    // 224+ multicast / reserved
    if (blocked) {
      throw new Error("SSRF block: private/reserved IPv4 '" + bare + "' in " + raw);
    }
  }
}

function fetchUrl(url, redirectCount, extraHeaders) {
  redirectCount = redirectCount || 0;
  if (redirectCount > 5) return Promise.reject(new Error("Too many redirects"));

  // Validate every URL — including each redirect destination — before connecting.
  try { assertSafeUrl(url); }
  catch (e) { return Promise.reject(e); }

  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, {
      headers: Object.assign({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Charset":  "UTF-8",
        "Cache-Control":   "no-cache",
        "Referer":         "https://www.google.com/",
      }, extraHeaders || {}),
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        let next;
        try {
          // Resolve relative redirects against the current URL, then validate.
          next = res.headers.location.startsWith("http")
            ? res.headers.location
            : new URL(res.headers.location, url).href;
          assertSafeUrl(next);
        } catch (e) {
          return reject(e);
        }
        return fetchUrl(next, redirectCount + 1, extraHeaders).then(resolve).catch(reject);
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end",  () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("Timeout: " + url)); });
  });
}

function postJson(url, payload, headers) {
  return new Promise((resolve, reject) => {
    const body    = JSON.stringify(payload);
    const urlObj  = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path:     urlObj.pathname,
      method:   "POST",
      headers:  Object.assign({
        "Content-Type":   "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(body, "utf8"),
      }, headers || {}),
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end",  () => {
        const text = Buffer.concat(chunks).toString("utf8");
        try { resolve(JSON.parse(text)); }
        catch (e) { reject(new Error("JSON parse failed: " + text.slice(0, 300))); }
      });
    });
    req.on("error", reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error("Groq timeout")); });
    req.write(body, "utf8");
    req.end();
  });
}

// ─── RETRY HELPER ──────────────────────────────────────────────────────────

/**
 * Retries an async function up to `maxAttempts` times with exponential backoff.
 * Retries on network errors and on HTTP-like status codes 429 / 5xx embedded in
 * thrown Error messages (Groq and Cloudinary surface these as thrown errors).
 *
 * @param {() => Promise<any>} fn        - Async factory called each attempt
 * @param {number}             maxAttempts
 * @param {number}             baseDelayMs - Initial delay; doubles each retry
 */
async function retryWithBackoff(fn, maxAttempts = 3, baseDelayMs = 1500) {
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const msg = (err.message || "").toLowerCase();
      const isRetryable =
        msg.includes("429") ||
        msg.includes("503") ||
        msg.includes("502") ||
        msg.includes("500") ||
        msg.includes("timeout") ||
        msg.includes("econnreset") ||
        msg.includes("enotfound");

      if (!isRetryable || attempt === maxAttempts) throw err;

      const delay = baseDelayMs * Math.pow(2, attempt - 1);
      console.warn(`  ⚠️  Attempt ${attempt}/${maxAttempts} failed (${err.message}). Retrying in ${delay}ms…`);
      await new Promise(res => setTimeout(res, delay));
    }
  }
  throw lastErr;
}

// ─── RSS READER ────────────────────────────────────────────────────────────

/**
 * Đọc một RSS feed, trả về mảng articles
 * Hỗ trợ cả RSS 2.0 và Atom
 */
async function fetchRssFeed(source) {
  console.log("📡  Fetching RSS: " + source.name + " ← " + source.url);
  let xml;
  try {
    xml = await fetchUrl(source.url, 0, {
      "Accept": "application/rss+xml, application/xml, text/xml, */*",
    });
  } catch(e) {
    console.warn("   ⚠️  " + source.name + " failed:", e.message);
    return [];
  }

  const articles = [];

  // Hỗ trợ RSS <item> và Atom <entry>
  const itemRe = /<(?:item|entry)>([\s\S]*?)<\/(?:item|entry)>/gi;
  let m;
  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[1];

    // Title — ưu tiên CDATA
    const titleM = block.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
    const title  = titleM ? decodeHtmlEntities(titleM[1].trim()) : "";

    // URL — <link>, <link href="...">, hoặc <guid isPermaLink="true">
    let url = "";
    const linkM = block.match(/<link>(?:<!\[CDATA\[)?(https?:\/\/[^<\]]+?)(?:\]\]>)?<\/link>/i)
               || block.match(/<link[^>]+href=["'](https?:\/\/[^"']+)["']/i)
               || block.match(/<guid[^>]*isPermaLink=["']true["'][^>]*>(https?:\/\/[^<]+)<\/guid>/i);
    if (linkM) url = linkM[1].trim();

    if (!url || !url.startsWith("http")) continue;

    // Description / summary
    const descM = block.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i)
               || block.match(/<summary[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/summary>/i)
               || block.match(/<content:encoded>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/content:encoded>/i);
    let description = descM ? decodeHtmlEntities(descM[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()).slice(0, 300) : "";

    // Published date — <pubDate> hoặc <published>
    const dateM = block.match(/<pubDate>([^<]+)<\/pubDate>/i)
               || block.match(/<published>([^<]+)<\/published>/i)
               || block.match(/<updated>([^<]+)<\/updated>/i);
    const publishedAt = dateM ? new Date(dateM[1].trim()).toISOString() : new Date().toISOString();

    // Ảnh — media:content, enclosure, hoặc og:image trong content
    let imageUrl = null;
    const mediaM = block.match(/<media:(?:content|thumbnail)[^>]+url=["']([^"']+)["']/i)
                || block.match(/<enclosure[^>]+url=["']([^"']+)["'][^>]+type=["']image/i);
    if (mediaM) imageUrl = mediaM[1];
    if (!imageUrl && descM) {
      const imgM = descM[1].match(/<img[^>]+src=["'](https?:\/\/[^"']+)["']/i);
      if (imgM) imageUrl = imgM[1];
    }

    articles.push({ url, title, description, imageUrl, publishedAt, sourceName: source.name });
  }

  console.log("   → " + articles.length + " articles from " + source.name);
  return articles;
}

// ─── TELEGRAM CHANNEL READER ─────────────────────────────────────────────

/**
 * Lấy N tin mới nhất từ kênh public @WatcherGuru.
 * Scrape trực tiếp https://t.me/s/WatcherGuru — Telegram tự host, không cần
 * xác thực, không bị Cloudflare chặn như các RSS proxy bên thứ ba.
 */
async function fetchTelegramMessages() {
  const pageUrl = "https://t.me/s/" + WATCHER_GURU_CHANNEL;
  console.log("📲  Fetching " + WATCHER_GURU_LIMIT + " latest posts from @" + WATCHER_GURU_CHANNEL + "...");
  console.log("   📡 Scraping: " + pageUrl);

  let html;
  try {
    html = await fetchUrl(pageUrl, 0, {
      "Accept":          "text/html,application/xhtml+xml,*/*",
      "Accept-Language": "en-US,en;q=0.9",
    });
  } catch (e) {
    console.warn("   ⚠️  Failed to fetch Telegram page:", e.message);
    return [];
  }

  const articles = [];

  // Tách từng message block dựa trên class tgme_widget_message_wrap
  const blocks = html.split("tgme_widget_message_wrap").slice(1);

  for (const block of blocks) {
    if (articles.length >= WATCHER_GURU_LIMIT) break;

    // Nội dung text
    const textM = block.match(/class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)<\/div>/i);
    if (!textM) continue;
    const rawText = textM[1].replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, "").trim();
    const text = decodeHtmlEntities(rawText);
    if (!text) continue;

    // Permalink tới từng message
    const urlM = block.match(/href="(https:\/\/t\.me\/[^"]+\/\d+)"/i);
    const url  = urlM ? urlM[1] : "https://t.me/" + WATCHER_GURU_CHANNEL;

    // Thời gian
    const dateM = block.match(/<time[^>]+datetime="([^"]+)"/i);
    const publishedAt = dateM ? new Date(dateM[1]).toISOString() : new Date().toISOString();

    // Dòng đầu làm title
    const lines = text.split("\n").filter(l => l.trim());
    const title       = (lines[0] || "WatcherGuru Alert").slice(0, 120);
    const description = lines.slice(1).join(" ").trim().slice(0, 300) || title;

    articles.push({ url, title, description, imageUrl: null, publishedAt, sourceName: "WatcherGuru (Telegram)" });
  }

  console.log("   → " + articles.length + " posts from @" + WATCHER_GURU_CHANNEL);
  return articles;
}

async function fetchTopNewsFromRss() {
  console.log("\n📰  Aggregating RSS from " + RSS_SOURCES.length + " sources + Telegram @" + WATCHER_GURU_CHANNEL + "...");

  const allArticles = [];

  // Lấy tin từ RSS feeds
  for (const source of RSS_SOURCES) {
    const items = await fetchRssFeed(source);
    allArticles.push(...items);
  }

  // Lấy tin từ Telegram @WatcherGuru (MTProto)
  const tgMessages = await fetchTelegramMessages();
  allArticles.push(...tgMessages);

  // Loại trùng URL
  const seen   = new Set();
  const unique = allArticles.filter(a => {
    if (seen.has(a.url)) return false;
    seen.add(a.url);
    return true;
  });

  // Bỏ qua ảnh từ Cointelegraph (thường bị block hotlink)
  unique.forEach(a => {
    if (a.imageUrl && a.imageUrl.includes("cointelegraph.com")) {
      a.imageUrl = null;
    }
  });

  // Ưu tiên WatcherGuru lên đầu, sau đó mới nhất trước
  unique.sort((a, b) => {
    const aIsWG = (a.sourceName || "").toLowerCase().includes("watcher") ? 0 : 1;
    const bIsWG = (b.sourceName || "").toLowerCase().includes("watcher") ? 0 : 1;
    if (aIsWG !== bIsWG) return aIsWG - bIsWG;
    return new Date(b.publishedAt) - new Date(a.publishedAt);
  });

  const result = unique.slice(0, TOP_N);
  const sourceCount = RSS_SOURCES.length + (tgMessages.length > 0 ? 1 : 0);
  console.log("📋  Collected: " + unique.length + " articles from " + sourceCount + " sources → keeping top " + result.length);
  return result;
}

// ─── ENRICH ARTICLE METADATA ───────────────────────────────────────────────

async function enrichArticle(article) {
  // RSS thường đã có title + description đủ dùng
  if (article.title && article.description && article.description.length > 80 && article.imageUrl) {
    console.log("  ✅ Metadata complete: " + article.title.slice(0, 60));
    return article;
  }

  // Chỉ fetch thêm nếu thiếu ảnh hoặc description quá ngắn
  console.log("  📄 Fetching extra metadata: " + article.url.slice(0, 80));
  try {
    const html = await fetchUrl(article.url);

    if (!article.description || article.description.length < 80) {
      const dm = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)
               || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i)
               || html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i);
      if (dm) article.description = decodeHtmlEntities(dm[1]).slice(0, 300);
    }

    if (!article.imageUrl) {
      const img = extractImage(html, article.url);
      // Bỏ qua ảnh Cointelegraph (thường bị block hotlink)
      if (img && !img.includes("cointelegraph.com")) {
        article.imageUrl = img;
      }
    }

    // Content snippet cho AI
    const cleanText = html
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<nav[\s\S]*?<\/nav>/gi, "")
      .replace(/<header[\s\S]*?<\/header>/gi, "")
      .replace(/<footer[\s\S]*?<\/footer>/gi, "")
      .replace(/<aside[\s\S]*?<\/aside>/gi, "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 1500);
    article.contentSnippet = decodeHtmlEntities(cleanText);

  } catch(e) {
    console.warn("  ⚠️  Could not fetch:", e.message);
  }

  return article;
}

function extractImage(html, baseUrl) {
  let m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
           || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
  if (m && m[1] && m[1].startsWith("http")) return m[1];

  m = html.match(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i)
    || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["']/i);
  if (m && m[1] && m[1].startsWith("http")) return m[1];

  const bodyMatch = html.match(/<(?:article|main|div[^>]+class=["'][^"']*(?:content|body|post|article)[^"']*["'])[^>]*>([\s\S]{0,8000})/i);
  const area      = bodyMatch ? bodyMatch[1] : html;
  const imgRe     = /<img[^>]+src=["']([^"']{10,})["'][^>]*/gi;
  while ((m = imgRe.exec(area)) !== null) {
    const tag = m[0];
    const w   = tag.match(/width=["'](\d+)["']/i);
    const h   = tag.match(/height=["'](\d+)["']/i);
    if (w && parseInt(w[1]) < 200) continue;
    if (h && parseInt(h[1]) < 150) continue;
    const src = m[1];
    if (src.startsWith("data:")) continue;
    if (src.startsWith("http"))  return src;
    if (src.startsWith("/")) { try { return new URL(src, baseUrl).href; } catch(_) {} }
  }
  return null;
}

// ─── CLOUDINARY ────────────────────────────────────────────────────────────

async function uploadToCloudinary(imageUrl, slug, altText, tags) {
  if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) return null;
  try {
    console.log("☁️  Upload Cloudinary:", imageUrl.slice(0, 80));
    const timestamp  = Math.floor(Date.now() / 1000).toString();
    const tagsStr    = (tags || []).slice(0, 5).join(",") || "crypto,bitcoin";
    const contextStr = "alt=" + altText.replace(/[|=]/g, " ") + "|caption=" + altText.replace(/[|=]/g, " ");
    const signParams = ["context=" + contextStr, "folder=xeonbit24/posts", "overwrite=true", "public_id=" + slug, "tags=" + tagsStr, "timestamp=" + timestamp].join("&");
    const signature  = crypto.createHash("sha1").update(signParams + CLOUDINARY_API_SECRET).digest("hex");

    const formData = [["file", imageUrl], ["public_id", slug], ["folder", "xeonbit24/posts"], ["overwrite", "true"], ["tags", tagsStr], ["context", contextStr], ["timestamp", timestamp], ["api_key", CLOUDINARY_API_KEY], ["signature", signature]];
    const boundary = "----Xeonbit24" + Date.now();
    const bodyStr  = formData.map(([k, v]) => "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + k + "\"\r\n\r\n" + v + "\r\n").join("") + "--" + boundary + "--\r\n";
    const bodyBuf  = Buffer.from(bodyStr, "utf8");

    const result = await new Promise((resolve, reject) => {
      const options = { hostname: "api.cloudinary.com", path: "/v1_1/" + CLOUDINARY_CLOUD_NAME + "/image/upload", method: "POST", headers: { "Content-Type": "multipart/form-data; boundary=" + boundary, "Content-Length": bodyBuf.length } };
      const req = https.request(options, (res) => {
        const chunks = [];
        res.on("data", c => chunks.push(c));
        res.on("end",  () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch(e) { reject(e); } });
      });
      req.on("error", reject);
      req.setTimeout(60000, () => { req.destroy(); reject(new Error("Cloudinary timeout")); });
      req.write(bodyBuf); req.end();
    });

    if (result.error) { console.warn("⚠️  Cloudinary error:", result.error.message); return null; }
    const transformedUrl = result.secure_url.replace("/upload/", "/upload/f_auto,q_auto,w_1200,h_630,c_fill,g_auto/");
    console.log("✅  Cloudinary OK:", result.public_id);
    return { url: transformedUrl, rawUrl: result.secure_url, publicId: result.public_id, width: result.width, height: result.height, format: result.format, alt: altText };
  } catch(err) {
    console.warn("⚠️  Cloudinary failed:", err.message);
    return null;
  }
}

// ─── POSTS STORAGE ─────────────────────────────────────────────────────────

function loadPosts() {
  try {
    if (fs.existsSync(POSTS_FILE)) return JSON.parse(fs.readFileSync(POSTS_FILE, "utf8"));
  } catch(e) { console.warn("Could not read posts.json:", e.message); }
  return { posts: [], publishedUrls: [], publishedBatchKeys: [] };
}

function savePosts(data) {
  fs.mkdirSync(path.dirname(POSTS_FILE), { recursive: true });
  fs.writeFileSync(POSTS_FILE, JSON.stringify(data, null, 2), "utf8");
  console.log("✅  Saved " + data.posts.length + " posts to docs/posts.json");
  saveSitemap(data.posts);
  saveRobots();
}

function saveSitemap(posts) {
  const base  = SITE_URL.replace(/\/$/, "");
  const today = new Date().toISOString().slice(0, 10);
  const pages = [
    { loc: base + "/", priority: "1.0", changefreq: "daily",   lastmod: today },
    ...posts.map(p => ({ loc: base + "/#" + (p.slug || p.id), priority: "0.8", changefreq: "monthly", lastmod: p.publishedAt ? p.publishedAt.slice(0, 10) : today })),
  ];
  const esc = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const xml  = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">',
    ...pages.map((u, i) => {
      const post   = posts[i - 1];
      const imgTag = post && post.image && post.image.url ? "\n    <image:image>\n      <image:loc>" + esc(post.image.url) + "</image:loc>\n      <image:title>" + esc(post.title) + "</image:title>\n      <image:caption>" + esc(post.image.alt || post.title) + "</image:caption>\n    </image:image>" : "";
      return "  <url>\n    <loc>" + u.loc + "</loc>\n    <lastmod>" + u.lastmod + "</lastmod>\n    <changefreq>" + u.changefreq + "</changefreq>\n    <priority>" + u.priority + "</priority>" + imgTag + "\n  </url>";
    }), "</urlset>"].join("\n");
  fs.writeFileSync(SITEMAP_FILE, xml, "utf8");
  console.log("🗺️   Sitemap: " + pages.length + " URLs → docs/sitemap.xml");
}

function saveRobots() {
  const base = SITE_URL.replace(/\/$/, "");
  fs.writeFileSync(ROBOTS_FILE, "User-agent: *\nAllow: /\n\nSitemap: " + base + "/sitemap.xml\n", "utf8");
  console.log("🤖  robots.txt updated");
}

// ─── GROQ AI – TỔNG HỢP TOP 10 TIN ───────────────────────────────────────

async function generateRoundupWithGroq(articles) {
  console.log("🤖  Groq AI synthesizing " + articles.length + " articles from RSS...");

  const now = new Date();
  const today = now.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
  const timeStr = now.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true, timeZone: "Asia/Ho_Chi_Minh" });
  const todayWithTime = today + " at " + timeStr + " (ICT)";
  const sourceNames  = [...new Set(articles.map(a => a.sourceName))].join(", ");

  const newsListText = articles.map((a, i) =>
    "[Article " + (i + 1) + "] " + (a.title || "(no title)") + "\n" +
    "Source: " + (a.sourceName || "RSS") + " | URL: " + a.url + "\n" +
    (a.description ? "Description: " + a.description.slice(0, 200) + "\n" : "") +
    (a.contentSnippet ? "Content: " + a.contentSnippet.slice(0, 400) + "\n" : "")
  ).join("\n---\n");

  const systemPrompt =
    "You are a world-class cryptocurrency and blockchain market analyst. " +
    "You have deep expertise in Bitcoin, Ethereum, DeFi, NFTs, altcoins, and global crypto markets. " +
    "Your task: receive the top " + articles.length + " latest crypto news articles and RETURN ONLY a valid UTF-8 JSON object. " +
    "No other text, no markdown, no code blocks, no explanations.";

  const userPrompt =
    "Below are the TOP " + articles.length + " latest crypto news articles from " + todayWithTime +
    ", aggregated from: " + sourceNames + ".\n" +
    "Write a comprehensive English crypto market roundup and analysis.\n\n" +
    "=== NEWS ARTICLES ===\n" + newsListText + "\n" +
    "=== REQUIREMENTS ===\n" +
    "- ALL content MUST be written in English\n" +
    "- Cover ALL " + articles.length + " articles, each with its own heading\n" +
    "- Structure: Overview intro → Individual analysis per article (by importance) → Overall market outlook → Key takeaways\n" +
    "- Highlight common trends and connections between events\n" +
    "- Explain technical terms clearly for a general crypto audience\n" +
    "- 800-1200 words, use HTML for content field\n" +
    "- Tags in English or coin names (max 6 tags)\n\n" +
    "ONLY return a JSON object, NOTHING else:\n" +
    "{\"title\":\"Crypto Roundup " + todayWithTime + ": [highlight summary]\"," +
    "\"summary\":\"2-3 sentence overview of the most important events\"," +
    "\"tags\":[\"bitcoin\",\"ethereum\",\"market\",\"crypto news\"]," +
    "\"content\":\"<p>Intro...</p><h2>1. [Top Story]</h2><p>Analysis...</p><h2>2. [...]</h2><p>...</p><h2>Market Outlook</h2><p>...</p><h2>Key Takeaways</h2><p>...</p>\"," +
    "\"readTime\":8}";

  const res = await retryWithBackoff(() => postJson(
    GROQ_URL,
    { model: GROQ_MODEL, messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }], temperature: 0.45, max_tokens: 3500 },
    { "Authorization": "Bearer " + GROQ_KEY }
  ), 3, 2000);

  if (res.error) throw new Error("Groq error: " + JSON.stringify(res.error));

  const raw  = ((res.choices || [])[0] || {}).message || {};
  const text = (raw.content || "").trim();
  console.log("📥  Groq raw (300c):", text.slice(0, 300));
  return parseJson(text, articles);
}

function parseJson(text, articles) {
  try { const p = JSON.parse(text); if (p && p.title) return p; } catch(_) {}
  const s = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  try { const p = JSON.parse(s); if (p && p.title) return p; } catch(_) {}
  const start = text.indexOf("{");
  if (start !== -1) {
    let depth = 0, end = -1, inStr = false, esc = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (esc)         { esc = false; continue; }
      if (ch === "\\") { esc = true;  continue; }
      if (ch === '"')  { inStr = !inStr; continue; }
      if (inStr)       continue;
      if (ch === "{")  depth++;
      else if (ch === "}") { if (--depth === 0) { end = i; break; } }
    }
    if (end !== -1) { try { const p = JSON.parse(text.slice(start, end + 1)); if (p && p.title) return p; } catch(_) {} }
  }
  console.warn("⚠️   Using regex fallback");
  const field = (k) => { const m = text.match(new RegExp('"' + k + '"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"', "i")); return m ? m[1].replace(/\\n/g, "\n").replace(/\\"/g, '"') : null; };
  const arr   = (k) => { const m = text.match(new RegExp('"' + k + '"\\s*:\\s*\\[([^\\]]+)\\]', "i")); return m ? (m[1].match(/"([^"]+)"/g) || []).map(x => x.replace(/"/g, "")) : []; };
  const num   = (k) => { const m = text.match(new RegExp('"' + k + '"\\s*:\\s*(\\d+)', "i")); return m ? parseInt(m[1]) : 8; };
  const title = field("title") || "Crypto Roundup: Top " + articles.length + " Stories";
  return {
    title,
    summary:  field("summary")  || "Summary of the latest " + articles.length + " crypto news articles.",
    content:  field("content")  || "<p>" + articles.map(a => "<b>" + (a.title || a.url) + "</b>").join("</p><p>") + "</p>",
    tags:     arr("tags").length ? arr("tags") : ["bitcoin", "crypto news", "market", "blockchain"],
    readTime: num("readTime"),
  };
}

// ─── SLUGIFY / DECODE ──────────────────────────────────────────────────────

function slugify(text) {
  return String(text)
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d").replace(/Đ/g, "d")
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

function decodeHtmlEntities(str) {
  return String(str || "")
    .replace(/&amp;/g,  "&")
    .replace(/&lt;/g,   "<")
    .replace(/&gt;/g,   ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g,  "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g,      (_, n) => String.fromCodePoint(parseInt(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}

// ─── MAIN ──────────────────────────────────────────────────────────────────

async function main() {
  console.log("=".repeat(60));
  console.log("🚀  Xeonbit24 – Crypto & Blockchain News RSS -", new Date().toISOString());
  console.log("📡  Sources:", RSS_SOURCES.map(s => s.name).join(", "));
  console.log("📋  Fetching top", TOP_N, "latest articles");
  console.log("=".repeat(60));

  const data = loadPosts();
  console.log("📚  Existing posts:", data.posts.length);

  // ─ Bước 1: Lấy top 10 tin từ RSS ─
  const cmcArticles = await fetchTopNewsFromRss();

  if (cmcArticles.length === 0) {
    console.error("❌  No articles fetched from RSS feeds. Exiting.");
    process.exit(1);
  }

  if (cmcArticles.length < 5) {
    console.error(`❌  Only ${cmcArticles.length} articles fetched (minimum 5 required). Check RSS feeds.`);
    process.exit(1);
  }

  // ─ Bước 2: Kiểm tra đã đăng chưa (dùng URL của 3 tin đầu làm batch key) ─
  const batchKey        = cmcArticles.slice(0, 3).map(a => a.url).join("|");
  const alreadyPosted   = !FORCE && (data.publishedBatchKeys || []).includes(batchKey);

  if (alreadyPosted) {
    console.log("ℹ️   This batch was already published. Use FORCE=true to override.");
    return;
  }

  console.log("\n📰  Article list (" + cmcArticles.length + " from RSS feeds):");
  cmcArticles.forEach((a, i) => console.log("  [" + (i + 1) + "] " + (a.title || a.url).slice(0, 70)));

  // ─ Bước 3: Enrich từng bài ─
  console.log("\n🔍  Enriching metadata...");
  const enriched = [];
  for (const article of cmcArticles) {
    try   { enriched.push(await enrichArticle(article)); }
    catch (e) { console.warn("  ⚠️  Skipping:", e.message); enriched.push(article); }
  }

  // ─ Bước 4: Chọn ảnh đại diện ─
  // Ưu tiên ảnh không phải Cointelegraph (bị block hotlink)
  const representativeArticle =
    enriched.find(a => a.imageUrl && !a.imageUrl.includes("cointelegraph.com")) ||
    enriched.find(a => a.imageUrl) ||
    enriched[0];
  const coverImageUrl = representativeArticle.imageUrl &&
    !representativeArticle.imageUrl.includes("cointelegraph.com")
      ? representativeArticle.imageUrl
      : null;
  console.log("\n🖼️   Cover image:", coverImageUrl || "(none — Cointelegraph skipped or no image)");

  // ─ Bước 5: Groq tổng hợp ─
  const generated = await generateRoundupWithGroq(enriched);

  // ─ Bước 6: Tạo post ─
  const slug = slugify(generated.title || "crypto-roundup-top-" + TOP_N + "-" + Date.now());
  const tags = (generated.tags && generated.tags.length) ? generated.tags : ["bitcoin", "crypto news", "market", "blockchain"];

  let imageObj = null;
  if (coverImageUrl) {
    const altText     = (generated.title || "Top tin crypto").slice(0, 120);
    const cloudResult = await uploadToCloudinary(coverImageUrl, slug, altText, tags);
    // Nếu Cloudinary thành công → dùng Cloudinary URL
    // Nếu thất bại → chỉ dùng URL gốc nếu KHÔNG phải Cointelegraph
    if (cloudResult) {
      imageObj = cloudResult;
    } else {
      console.warn("⚠️  Cloudinary failed — using original URL (non-Cointelegraph)");
      imageObj = { url: coverImageUrl, rawUrl: coverImageUrl, alt: altText };
    }
  }

  // Thêm danh sách nguồn vào cuối bài (không dùng link để tối ưu SEO)
  const sourcesList      = enriched.map((a, i) =>
    '<li>[' + (i + 1) + '] ' +
    (a.title || a.sourceName || "RSS").replace(/</g, "&lt;").replace(/>/g, "&gt;") +
    ' — <em>' + (a.sourceName || "RSS") + '</em></li>'
  ).join("\n");
  const contentWithSources = (generated.content || "") +
    "\n<h2>Sources</h2>\n<ol>\n" + sourcesList + "\n</ol>";

  const post = {
    id:               Date.now().toString(),
    title:            generated.title   || "Crypto Roundup: Top " + TOP_N + " Stories",
    summary:          generated.summary || "",
    content:          contentWithSources,
    tags,
    readTime:         generated.readTime || 8,
    image:            imageObj,
    sourceUrl:        enriched[0].url,
    sourceTitle:      enriched.map(a => a.sourceName).filter((v,i,a) => a.indexOf(v)===i).join(" / "),
    articleCount:     enriched.length,
    articlesIncluded: enriched.map(a => ({ title: a.title, url: a.url, source: a.sourceName })),
    publishedAt:      new Date().toISOString(),
    slug,
  };

  data.posts             = data.posts             || [];
  data.publishedUrls     = data.publishedUrls     || [];
  data.publishedBatchKeys = data.publishedBatchKeys || [];

  data.posts.unshift(post);
  enriched.forEach(a => { if (a.url && !data.publishedUrls.includes(a.url)) data.publishedUrls.push(a.url); });
  if (data.publishedUrls.length > 500) data.publishedUrls = data.publishedUrls.slice(-500);
  data.publishedBatchKeys.push(batchKey);
  if (data.publishedBatchKeys.length > 200) data.publishedBatchKeys = data.publishedBatchKeys.slice(-200);

  savePosts(data);

  console.log("\n🎉  Published:", post.title);
  console.log("📊  Aggregated:", post.articleCount, "articles from", RSS_SOURCES.map(s => s.name).join(", "));
  if (post.image) console.log("🖼️   Thumbnail:", post.image.url);
  console.log("🏷️   Tags:", post.tags.join(", "));
  console.log("=".repeat(60));

  // ─ Bước 7: Chia sẻ lên Telegram ─
  const postUrl = SITE_URL.replace(/\/$/, "") + "/#" + post.slug;
  const tgMessage = buildTelegramMessage(post, postUrl);
  await sendTelegramMessage(tgMessage);
}

// ─── TELEGRAM SHARING ──────────────────────────────────────────────────────

/**
 * Gửi tin nhắn lên nhóm Telegram qua Bot API.
 * Dùng plain text để tránh lỗi parse MarkdownV2 với nội dung động từ AI.
 */
function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    console.log("ℹ️   Skipping Telegram: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.");
    return Promise.resolve();
  }

  const payload = JSON.stringify({
    chat_id: TELEGRAM_CHAT_ID,
    text:    text,
    // Không dùng parse_mode để tránh lỗi ký tự đặc biệt từ nội dung AI
    link_preview_options: { is_disabled: false },
  });

  return new Promise((resolve) => {
    const options = {
      hostname: "api.telegram.org",
      path:     "/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage",
      method:   "POST",
      headers:  {
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    };

    const req = https.request(options, res => {
      let body = "";
      res.on("data", chunk => { body += chunk; });
      res.on("end", () => {
        try {
          const json = JSON.parse(body);
          if (json.ok) {
            console.log("📨  Shared to Telegram (message_id:", json.result.message_id + ")");
          } else {
            console.warn("⚠️   Telegram API error:", json.description);
          }
        } catch (e) {
          console.warn("⚠️   Failed to parse Telegram response:", e.message);
        }
        resolve();
      });
    });

    req.on("error", err => {
      console.warn("⚠️   Failed to send Telegram message:", err.message);
      resolve();
    });

    req.write(payload);
    req.end();
  });
}

/** Tạo nội dung tin nhắn Telegram plain text. */
function buildTelegramMessage(post, postUrl) {
  const title   = post.title || "";
  const summary = (post.summary || "").slice(0, 280);
  const tags    = post.tags.slice(0, 5).map(t => "#" + t.replace(/\s+/g, "_")).join(" ");
  const count   = post.articleCount || 0;

  return (
    "🔥 " + title + "\n\n" +
    (summary ? summary + "\n\n" : "") +
    "📰 Aggregated from " + count + " latest articles.\n\n" +
    "👉 " + postUrl + "\n\n" +
    tags
  );
}


main().catch(err => {
  console.error("❌  Fatal error:", err.message);
  process.exit(1);
});
