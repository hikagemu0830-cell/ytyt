// server.js — Render等で動くNode.js版 中継(リバース)プロキシ
// 要件: Node.js 20+ / package.json に "type": "module"
//
// 構成（通信を丸ごとProxy経由にする3層）
//  1) サーバー側 : HTML/CSSのURLを全部書き換え（外部サイトは /~p/<scheme>/<host>/<path> 経由）
//  2) ブラウザ側 : /~shim.js が fetch/XHR/WebSocket/動的要素/cookie などをProxy化
//  3) ServiceWorker: /~sw.js がページから出る全リクエストを最終的にProxyへ回収
// 従来どおり、TARGET のサイトは「ルート直下」でそのまま中継されます（互換維持）。
//
// 環境変数
//  TARGET            中継の主対象（既定 https://www.b-ch.com）
//  PORT              Renderが自動で渡す
//  ALLOW_EXTERNAL    0 にすると TARGET 以外のホストへの中継を禁止（既定は許可）
//  RETRIES           GET/HEAD の再試行回数（既定 2）
//  HEADER_TIMEOUT_MS 上流のヘッダ待ち上限（既定 25000）
//  BODY_TIMEOUT_MS   HTML/CSS本文の受信上限（既定 60000）

import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";
import crypto from "node:crypto";
import { Readable, pipeline } from "node:stream";

const TARGET = process.env.TARGET || "https://abema.tv";
const PORT = Number(process.env.PORT) || 10000;
const ALLOW_EXTERNAL = process.env.ALLOW_EXTERNAL !== "0";
const RETRIES = Number.isFinite(Number(process.env.RETRIES)) ? Number(process.env.RETRIES) : 2;
const HEADER_TIMEOUT = Number(process.env.HEADER_TIMEOUT_MS) || 25000;
const BODY_TIMEOUT = Number(process.env.BODY_TIMEOUT_MS) || 60000;
const MAX_REWRITE_BYTES = 20 * 1024 * 1024;
const MAX_BODY_BYTES = 100 * 1024 * 1024;
const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const BASE = new URL(TARGET);
const BARE = BASE.hostname.replace(/^www\./i, "");
const SITE_HOSTS = [BARE, "www." + BARE];
const isSiteHost = (h) => SITE_HOSTS.includes(String(h).toLowerCase());
const P = "/~p/"; // 外部サイト用: /~p/https/host/path
const WS = "/~ws/"; // WebSocket用: /~ws/wss/host/path
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ───────────────────────── Cookie名の名前空間（サーバー/ブラウザ共通） ─────────────────────────
// 1つのProxyドメインに複数サイトのcookieが混ざらないよう、サイトごとに接頭辞を付ける
function ckey(h) {
  var p = String(h).toLowerCase().split(".");
  var n = 2;
  if (p.length >= 3 && p[p.length - 1].length === 2 && /^(co|com|ne|or|go|ac|ad|ed|gr|lg|org|net|gov|edu)$/.test(p[p.length - 2])) n = 3;
  return p.slice(-n).join(".");
}
const CK = (h) => "__px_" + ckey(h) + "__";

// ───────────────────────── URL変換 ─────────────────────────
function toProxy(href, myOrigin) {
  let u;
  try { u = new URL(href); } catch { return href; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return href;
  if (isSiteHost(u.hostname)) return myOrigin + u.pathname + u.search + u.hash;
  return myOrigin + P + u.protocol.slice(0, -1) + "/" + u.host + u.pathname + u.search + u.hash;
}

function parseProxyPath(pathname) {
  if (!pathname.startsWith(P)) return null;
  const m = /^(https?)\/([^/]+)(\/.*)?$/.exec(pathname.slice(P.length));
  return m ? { origin: m[1] + "://" + m[2], path: m[3] || "/" } : null;
}

// Proxy上のURL → 本当のURL
function realFromProxyUrl(str, myOrigin) {
  try {
    const u = new URL(str);
    if (u.origin !== myOrigin) return u;
    if (u.pathname.startsWith("/~") && !u.pathname.startsWith(P)) return null;
    const p = parseProxyPath(u.pathname);
    return p ? new URL(p.origin + p.path + u.search + u.hash) : new URL(BASE.origin + u.pathname + u.search + u.hash);
  } catch {
    return null;
  }
}

// このリクエストが最終的に取りに行く上流URLを決める
function resolveUpstream(req, url, myOrigin) {
  const p = parseProxyPath(url.pathname);
  if (p) return new URL(p.origin + p.path + url.search);
  // /~p/ でないルート相対パス: Refererが外部サイトのProxyページならそのサイトへ、なければTARGETへ
  let origin = BASE.origin;
  if (req.headers.referer) {
    try {
      const r = new URL(req.headers.referer);
      if (r.origin === myOrigin) {
        const real = realFromProxyUrl(req.headers.referer, myOrigin);
        if (real) origin = real.origin;
      }
    } catch {}
  }
  return new URL(origin + url.pathname + url.search);
}

// ───────────────────────── SSRF対策（社内/ローカル宛を拒否） ─────────────────────────
const dnsCache = new Map();
function privateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const s = ip.toLowerCase();
  if (s.startsWith("::ffff:") && net.isIPv4(s.slice(7))) return privateIp(s.slice(7));
  return s === "::1" || s === "::" || s.startsWith("fc") || s.startsWith("fd") || s.startsWith("fe80");
}
async function assertPublic(hostname) {
  const h = String(hostname).replace(/^\[|\]$/g, "").toLowerCase();
  if (isSiteHost(h)) return;
  if (!ALLOW_EXTERNAL) throw httpErr(403, "このサーバーはTARGET以外への中継を許可していません");
  if (/^(localhost|.*\.localhost|.*\.local|.*\.internal)$/.test(h)) throw httpErr(403, "blocked host");
  const c = dnsCache.get(h);
  if (c && c.exp > Date.now()) {
    if (c.bad) throw httpErr(403, "blocked host");
    return;
  }
  let bad;
  if (net.isIP(h)) bad = privateIp(h);
  else bad = (await dns.lookup(h, { all: true })).some((x) => privateIp(x.address));
  if (dnsCache.size > 2000) dnsCache.clear();
  dnsCache.set(h, { bad, exp: Date.now() + 60000 });
  if (bad) throw httpErr(403, "blocked host");
}
function httpErr(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// ───────────────────────── HTML / CSS の書き換え ─────────────────────────
const SKIP_RE = /^(#|javascript:|mailto:|tel:|data:|blob:|about:|sms:|intent:|market:|ws:|wss:)/i;

function rewriteUrl(v, base, my) {
  const s = v.trim();
  if (!s || SKIP_RE.test(s) || s.startsWith(my + P)) return v;
  try {
    return toProxy(new URL(s, base).href, my).replace(/"/g, "%22").replace(/'/g, "%27");
  } catch {
    return v;
  }
}

function rewriteSrcset(v, base, my) {
  return v.replace(/([^\s,]\S*)(\s+[^\s,]+)?(\s*,\s*|\s*$)/g, (m, u, d, s) => rewriteUrl(u, base, my) + (d || "") + s);
}

function rewriteCss(css, base, my) {
  return css
    .replace(/url\(\s*(["']?)([^"')]*?)\1\s*\)/gi, (m, q, u) => {
      const r = rewriteUrl(u, base, my);
      return r === u ? m : "url(" + q + r + q + ")";
    })
    .replace(/@import\s+(["'])([^"']+)\1/gi, (m, q, u) => "@import " + q + rewriteUrl(u, base, my) + q);
}

const ATTR_RE = /([^\s"'<>\/=]+)(\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
const URL_ATTRS = new Set(["href", "src", "action", "poster", "formaction", "background", "data-src", "data-original", "data-lazy-src", "data-href"]);
const SRCSET_ATTRS = new Set(["srcset", "imagesrcset", "data-srcset"]);

function rewriteTag(name, attrs, base, my) {
  const tag = name.toLowerCase();
  if (tag === "base") return "";
  let meta = "";
  if (tag === "meta") {
    const he = /http-equiv\s*=\s*["']?([\w-]+)/i.exec(attrs);
    meta = he ? he[1].toLowerCase() : "";
    if (meta === "content-security-policy" || meta === "content-security-policy-report-only") return "";
  }
  attrs = attrs.replace(ATTR_RE, (m, n, eq, a, b, c) => {
    const k = n.toLowerCase();
    const val = a ?? b ?? c ?? "";
    const q = b !== undefined ? "'" : '"';
    let nv = val;
    if (k === "integrity") return "";
    if (URL_ATTRS.has(k) || (k === "data" && tag === "object")) nv = rewriteUrl(val, base, my);
    else if (SRCSET_ATTRS.has(k)) nv = rewriteSrcset(val, base, my);
    else if (k === "style") nv = rewriteCss(val, base, my);
    else if (tag === "meta" && k === "charset") nv = "utf-8";
    else if (tag === "meta" && k === "content" && meta === "content-type") nv = val.replace(/charset\s*=\s*[\w.:-]+/i, "charset=utf-8");
    else if (tag === "meta" && k === "content" && meta === "refresh")
      nv = val.replace(/(url\s*=\s*)(['"]?)([^'";]+)\2/i, (x, p, qq, u) => p + qq + rewriteUrl(u, base, my) + qq);
    else return m;
    return n + eq + q + nv + q;
  });
  return "<" + name + attrs + ">";
}

const TOKEN_RE =
  /<!--[\s\S]*?-->|<(script|style)\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]*?)<\/\1\s*>|<([a-zA-Z][\w:-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/gi;

let SHIM_VER = "0";

function rewriteHtml(html, upstream, my) {
  let base = upstream.href;
  const bm = /<base\s[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(html);
  if (bm) {
    try { base = new URL(bm[1] ?? bm[2] ?? bm[3], upstream).href; } catch {}
  }
  let out = html.replace(TOKEN_RE, (m, sname, sattrs, sbody, tname, tattrs) => {
    if (m.startsWith("<!--")) return m;
    if (sname) {
      const open = rewriteTag(sname, sattrs, base, my);
      const body = sname.toLowerCase() === "style" ? rewriteCss(sbody, base, my) : sbody;
      return open + body + "</" + sname + ">";
    }
    return rewriteTag(tname, tattrs, base, my);
  });

  // 断片(HTMLの一部だけ返すAPI)にはshimを入れない
  if (/<(html|head|body|!doctype)/i.test(out.slice(0, 4096))) {
    const shim = `<script src="/~shim.js?v=${SHIM_VER}"></script>`;
    if (/<head[\s>]/i.test(out)) out = out.replace(/<head(\s[^>]*)?>/i, (m) => m + shim);
    else if (/<html[\s>]/i.test(out)) out = out.replace(/<html(\s[^>]*)?>/i, (m) => m + shim);
    else out = out.replace(/^(\s*<!doctype[^>]*>)?/i, (m) => m + shim);
  }
  return out;
}

// 文字コード（Shift_JIS / EUC-JP 等）を判定してUTF-8に統一
function charsetOf(type, buf) {
  let m = /charset\s*=\s*["']?([\w.:-]+)/i.exec(type || "");
  if (!m) {
    const head = buf.subarray(0, 4096).toString("latin1");
    m = /<meta[^>]+charset\s*=\s*["']?([\w.:-]+)/i.exec(head) || /^@charset\s+["']([\w.:-]+)["']/i.exec(head);
  }
  return (m ? m[1] : "utf-8").toLowerCase();
}
function decode(buf, cs) {
  try { return new TextDecoder(cs).decode(buf); } catch { return buf.toString("utf8"); }
}

// ───────────────────────── Cookie ─────────────────────────
function rewriteSetCookie(line, host, secureProxy) {
  const parts = line.split(";").map((s) => s.trim());
  const nv = parts.shift();
  if (!nv || !nv.includes("=")) return null;
  const out = [CK(host) + nv];
  for (const a of parts) {
    const k = a.split("=")[0].toLowerCase();
    if (["domain", "path", "secure", "samesite", "partitioned"].includes(k)) continue;
    out.push(a);
  }
  out.push("Path=/");
  if (secureProxy) out.push("Secure", "SameSite=None");
  else out.push("SameSite=Lax");
  return out.join("; ");
}
function cookieFor(req, hostname) {
  const ck = CK(hostname);
  return (req.headers.cookie || "")
    .split(/;\s*/)
    .filter((c) => c.startsWith(ck))
    .map((c) => c.slice(ck.length))
    .join("; ");
}

// ───────────────────────── ヘッダ処理 ─────────────────────────
const DROP_REQ = new Set(["host", "connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "cookie", "referer", "origin", "accept-encoding", "expect", "forwarded", "via", "priority"]);
const DROP_REQ_RE = /^(sec-fetch-|cf-|rndr|render-|x-render|x-forwarded|x-real-ip|x-request|true-client-ip)/;

function buildUpstreamHeaders(req, upstream, myOrigin) {
  const h = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (DROP_REQ.has(k) || DROP_REQ_RE.test(k)) continue;
    if (Array.isArray(v)) v.forEach((x) => h.append(k, x));
    else if (v != null) h.set(k, v);
  }
  if (!h.has("user-agent")) h.set("user-agent", DEFAULT_UA);
  const cookie = cookieFor(req, upstream.hostname);
  if (cookie) h.set("cookie", cookie);
  const ref = req.headers.referer ? realFromProxyUrl(req.headers.referer, myOrigin) : null;
  if (ref) ref.hash = "";
  h.set("referer", ref ? ref.href : upstream.origin + "/");
  if ((req.headers.origin && req.headers.origin !== "null") || (req.method !== "GET" && req.method !== "HEAD"))
    h.set("origin", ref ? ref.origin : upstream.origin);
  return h;
}

const DROP_RES = new Set(["content-security-policy", "content-security-policy-report-only", "x-frame-options", "strict-transport-security", "public-key-pins", "report-to", "nel", "cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "permissions-policy", "alt-svc", "link", "set-cookie", "content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "location", "refresh", "content-location", "clear-site-data"]);

function corsHeaders(req) {
  const o = req.headers.origin;
  return {
    "access-control-allow-origin": o && o !== "null" ? o : "*",
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": req.headers["access-control-request-headers"] || "*",
    "access-control-expose-headers": "*",
    "access-control-max-age": "86400",
    vary: "Origin",
  };
}

function responseHeaders(r, req, upstream, myOrigin) {
  const h = {};
  for (const [k, v] of r.headers) {
    if (DROP_RES.has(k) || k.startsWith("access-control-")) continue;
    h[k] = v;
  }
  Object.assign(h, corsHeaders(req));
  const sc = typeof r.headers.getSetCookie === "function" ? r.headers.getSetCookie() : [];
  const cookies = sc.map((c) => rewriteSetCookie(c, upstream.hostname, myOrigin.startsWith("https"))).filter(Boolean);
  if (cookies.length) h["set-cookie"] = cookies;
  return h;
}

// ───────────────────────── 上流への取得（再試行・タイムアウト付き） ─────────────────────────
async function fetchUpstream(upstream, init, canRetry, res) {
  let lastErr;
  const tries = canRetry ? RETRIES : 0;
  for (let i = 0; i <= tries; i++) {
    const ac = new AbortController();
    const onClose = () => ac.abort();
    res.once("close", onClose);
    const timer = setTimeout(() => ac.abort(new Error("upstream timeout")), HEADER_TIMEOUT);
    try {
      const r = await fetch(upstream, { ...init, signal: ac.signal, redirect: "manual" });
      clearTimeout(timer);
      if (canRetry && [502, 503, 504].includes(r.status) && i < tries) {
        res.off("close", onClose);
        r.body?.cancel().catch(() => {});
        await sleep(300 * (i + 1));
        continue;
      }
      return { r, ac };
    } catch (e) {
      clearTimeout(timer);
      res.off("close", onClose);
      lastErr = e;
      if (res.destroyed) throw e;
      await sleep(300 * (i + 1));
    }
  }
  throw lastErr;
}

async function readBody(req) {
  if (req.method === "GET" || req.method === "HEAD") return undefined;
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > MAX_BODY_BYTES) throw httpErr(413, "Payload Too Large");
    chunks.push(c);
  }
  return chunks.length ? Buffer.concat(chunks) : undefined;
}

// ───────────────────────── エラー表示（落ちずに必ず応答） ─────────────────────────
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function sendError(req, res, err) {
  if (res.destroyed) return;
  const text = String(err && (err.name + " " + err.message + " " + (err.cause && (err.cause.code || err.cause.message)) || err));
  const status = (err && err.status) || (/timeout|abort/i.test(text) ? 504 : 502);
  const detail = (err && err.cause && (err.cause.code || err.cause.message)) || (err && err.message) || "error";
  const wantsHtml = /text\/html/i.test(req.headers.accept || "") && req.method !== "HEAD";
  if (!wantsHtml) {
    res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...corsHeaders(req) });
    return res.end(req.method === "HEAD" ? undefined : `Proxy error ${status}: ${detail}`);
  }
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>中継エラー</title>
<body style="font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 20px;color:#222">
<h2>ページを取得できませんでした (${status})</h2><p style="color:#666;word-break:break-all">${esc(detail)}</p>
<button onclick="location.reload()" style="padding:10px 18px;font-size:16px">再読み込み</button></body>`);
}

// ───────────────────────── メイン処理 ─────────────────────────
async function handle(req, res) {
  if (!req.url || req.url[0] !== "/") {
    res.writeHead(400, { "content-type": "text/plain" });
    return res.end("Bad Request");
  }
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "localhost").split(",")[0].trim();
  const myOrigin = `${proto}://${host}`;
  const url = new URL("http://local" + req.url); // "//x" をホストと誤解釈させない

  // 内部エンドポイント
  if (url.pathname === "/~health") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("ok");
  }
  if (url.pathname === "/~shim.js") {
    res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "public, max-age=3600" });
    return res.end(SHIM_JS);
  }
  if (url.pathname === "/~sw.js") {
    res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-cache", "service-worker-allowed": "/" });
    return res.end(SW_JS);
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204, corsHeaders(req));
    return res.end();
  }

  const upstream = resolveUpstream(req, url, myOrigin);
  if (upstream.hostname.toLowerCase() === host.replace(/:\d+$/, "").toLowerCase() && !isSiteHost(upstream.hostname))
    throw httpErr(508, "Loop detected");
  await assertPublic(upstream.hostname);

  const body = await readBody(req);
  const headers = buildUpstreamHeaders(req, upstream, myOrigin);
  const isDocReq = /text\/html/i.test(req.headers.accept || "");
  if (isDocReq) {
    headers.delete("if-none-match");
    headers.delete("if-modified-since");
  }
  const canRetry = req.method === "GET" || req.method === "HEAD";
  const { r, ac } = await fetchUpstream(upstream, { method: req.method, headers, body }, canRetry, res);
  const status = r.status;
  const hdrs = responseHeaders(r, req, upstream, myOrigin);

  // リダイレクト: ステータスを保ったままLocationをProxy側へ
  const loc = r.headers.get("location");
  if (loc && status >= 300 && status < 400) {
    let dest;
    try { dest = toProxy(new URL(loc, upstream).href, myOrigin); } catch { dest = loc; }
    r.body?.cancel().catch(() => {});
    res.writeHead(status, { ...hdrs, location: dest, "cache-control": "no-store" });
    return res.end();
  }

  const type = r.headers.get("content-type") || "";
  const isHtml = /^(text\/html|application\/xhtml\+xml)/i.test(type);
  const isCss = /^text\/css/i.test(type);
  const lenH = r.headers.get("content-length");
  const enc = r.headers.get("content-encoding");
  const noBody = req.method === "HEAD" || [204, 205, 304].includes(status) || !r.body;

  if (noBody) {
    if (lenH && !enc && !isHtml && !isCss) hdrs["content-length"] = lenH;
    res.writeHead(status, hdrs);
    r.body?.cancel().catch(() => {});
    return res.end();
  }

  // HTML / CSS は読み込んで書き換え
  if ((isHtml || isCss) && !(Number(lenH) > MAX_REWRITE_BYTES)) {
    const timer = setTimeout(() => ac.abort(new Error("body timeout")), BODY_TIMEOUT);
    let buf;
    try {
      buf = Buffer.from(await r.arrayBuffer());
    } finally {
      clearTimeout(timer);
    }
    const text = decode(buf, charsetOf(type, buf));
    const out = Buffer.from(isHtml ? rewriteHtml(text, upstream, myOrigin) : rewriteCss(text, upstream.href, myOrigin), "utf8");
    hdrs["content-type"] = (isHtml ? "text/html" : "text/css") + "; charset=utf-8";
    hdrs["content-length"] = out.length;
    if (isHtml) {
      hdrs["cache-control"] = "no-store";
      delete hdrs.etag;
      delete hdrs["last-modified"];
    }
    res.writeHead(status, hdrs);
    return res.end(out);
  }

  // それ以外（画像・動画・JS・JSON等）はストリーム転送（Range/206もそのまま）
  if (lenH && !enc) hdrs["content-length"] = lenH;
  res.writeHead(status, hdrs);
  pipeline(Readable.fromWeb(r.body), res, () => {});
}

// ───────────────────────── WebSocket 中継 ─────────────────────────
function handleUpgrade(req, socket, head) {
  try {
    const url = new URL("http://local" + req.url);
    const m = /^\/~ws\/(wss?)\/([^/]+)(\/.*)?$/.exec(url.pathname);
    if (!m) return socket.destroy();
    const secure = m[1] === "wss";
    const hostport = m[2];
    const path = (m[3] || "/") + url.search;
    const hm = /^(.*?)(?::(\d+))?$/.exec(hostport);
    const hostname = hm[1];
    const port = Number(hm[2]) || (secure ? 443 : 80);
    assertPublic(hostname)
      .then(() => {
        const up = secure ? tls.connect({ host: hostname, port, servername: hostname }) : net.connect({ host: hostname, port });
        up.once(secure ? "secureConnect" : "connect", () => {
          const lines = [`GET ${path} HTTP/1.1`, `Host: ${hostport}`];
          for (let i = 0; i < req.rawHeaders.length; i += 2) {
            const k = req.rawHeaders[i];
            const kl = k.toLowerCase();
            if (["host", "origin", "cookie", "referer"].includes(kl) || DROP_REQ_RE.test(kl)) continue;
            lines.push(`${k}: ${req.rawHeaders[i + 1]}`);
          }
          lines.push(`Origin: ${secure ? "https" : "http"}://${hostport}`);
          const cookie = cookieFor(req, hostname);
          if (cookie) lines.push(`Cookie: ${cookie}`);
          up.write(lines.join("\r\n") + "\r\n\r\n");
          if (head && head.length) up.write(head);
          socket.pipe(up);
          up.pipe(socket);
        });
        up.on("error", () => socket.destroy());
        up.on("close", () => socket.destroy());
        socket.on("error", () => up.destroy());
        socket.on("close", () => up.destroy());
      })
      .catch(() => socket.destroy());
  } catch {
    socket.destroy();
  }
}

// ───────────────────────── ブラウザ側 Proxy (shim) ─────────────────────────
function makeShim() {
  return String.raw`(function(){
"use strict";
if(window.__pxShim)return;window.__pxShim=1;
var O=location.origin,P=${JSON.stringify(P)},WSP=${JSON.stringify(WS)},T=${JSON.stringify(BASE.origin)},HOSTS=${JSON.stringify(SITE_HOSTS)};
var ckey=${ckey.toString()};
function isSite(h){return HOSTS.indexOf(String(h).toLowerCase())>=0}
function parseP(pn){
  if(pn.indexOf(P)!==0)return null;
  var m=/^(https?)\/([^\/]+)(\/.*)?$/.exec(pn.slice(P.length));
  return m?{origin:m[1]+"://"+m[2],path:m[3]||"/"}:null;
}
function realBase(){
  try{var p=parseP(location.pathname);return p?new URL(p.origin+p.path+location.search):new URL(T+location.pathname+location.search)}
  catch(e){return new URL(T)}
}
var SKIP=/^(#|javascript:|mailto:|tel:|data:|blob:|about:|sms:|ws:|wss:)/i;
// どんなURLでもProxy経由のURLへ（何度通しても結果は同じ）
function prox(h){
  try{
    if(h==null)return h;
    if(typeof h==="object"&&h.href)h=h.href;
    var t=String(h).trim();
    if(!t||SKIP.test(t))return h;
    var u=new URL(t,location.href);
    if(u.protocol!=="http:"&&u.protocol!=="https:")return h;
    if(u.origin===O){
      if(u.pathname.indexOf(P)===0||u.pathname.indexOf("/~")===0)return u.href;
      var rb=realBase();
      u=new URL(rb.origin+u.pathname+u.search+u.hash);
    }
    if(isSite(u.hostname))return O+u.pathname+u.search+u.hash;
    return O+P+u.protocol.slice(0,-1)+"/"+u.host+u.pathname+u.search+u.hash;
  }catch(e){return h}
}
function wsu(u){
  try{
    var x=new URL(String(u),location.href),rb=realBase(),sec;
    var scheme=location.protocol==="https:"?"wss://":"ws://";
    if(x.protocol==="ws:"||x.protocol==="wss:")sec=x.protocol==="wss:";
    else if(x.protocol==="http:"||x.protocol==="https:")sec=x.protocol==="https:";
    else return u;
    if(x.host===location.host){
      if(x.pathname.indexOf(WSP)===0)return scheme+location.host+x.pathname+x.search;
      return scheme+location.host+WSP+(rb.protocol==="https:"?"wss":"ws")+"/"+rb.host+x.pathname+x.search;
    }
    return scheme+location.host+WSP+(sec?"wss":"ws")+"/"+x.host+x.pathname+x.search;
  }catch(e){return u}
}
var sa=Element.prototype.setAttribute;

// ── Cookie（サイトごとの名前空間に分離）
function ck(){return "__px_"+ckey(realBase().hostname)+"__"}
try{
  var cd=Object.getOwnPropertyDescriptor(Document.prototype,"cookie");
  Object.defineProperty(Document.prototype,"cookie",{configurable:true,enumerable:cd.enumerable,
    get:function(){
      var p=ck();
      return cd.get.call(this).split(/;\s*/).filter(function(c){return c.indexOf(p)===0}).map(function(c){return c.slice(p.length)}).join("; ");
    },
    set:function(v){
      var parts=String(v).split(";"),nv=parts.shift().trim();
      var rest=parts.map(function(a){return a.trim()}).filter(function(a){var k=a.split("=")[0].toLowerCase();return a&&k!=="domain"&&k!=="path"&&k!=="samesite"&&k!=="partitioned"});
      cd.set.call(this,[ck()+nv].concat(rest).concat(["path=/"]).join("; "));
    }});
}catch(e){}

// ── fetch / XHR / beacon / SSE / WebSocket / Worker
try{if(window.fetch){var f0=window.fetch;window.fetch=function(i,o){
  var n=i;
  try{if(typeof Request!=="undefined"&&i instanceof Request)n=new Request(prox(i.url),i);else n=prox(i)}catch(e){n=i}
  return f0.call(this,n,o)}}}catch(e){}
try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){var a=[].slice.call(arguments);a[1]=prox(u);return xo.apply(this,a)}}catch(e){}
try{if(navigator.sendBeacon){var sb=navigator.sendBeacon;navigator.sendBeacon=function(u,d){return sb.call(navigator,prox(u),d)}}}catch(e){}
function wrapCtor(name,fn){
  try{var C=window[name];if(!C)return;
    window[name]=new Proxy(C,{construct:function(t,a,nt){a=[].slice.call(a);a[0]=fn(a[0]);return Reflect.construct(t,a,nt)}});
  }catch(e){}
}
wrapCtor("WebSocket",wsu);wrapCtor("EventSource",prox);wrapCtor("Worker",prox);wrapCtor("SharedWorker",prox);

// ── 要素のURLプロパティ / setAttribute
[["HTMLImageElement","src"],["HTMLScriptElement","src"],["HTMLLinkElement","href"],["HTMLAnchorElement","href"],["HTMLAreaElement","href"],["HTMLIFrameElement","src"],["HTMLSourceElement","src"],["HTMLMediaElement","src"],["HTMLTrackElement","src"],["HTMLEmbedElement","src"],["HTMLObjectElement","data"],["HTMLInputElement","src"],["HTMLFormElement","action"]].forEach(function(p){
  try{
    var proto=window[p[0]]&&window[p[0]].prototype;if(!proto)return;
    var d=Object.getOwnPropertyDescriptor(proto,p[1]);if(!d||!d.set)return;
    Object.defineProperty(proto,p[1],{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){d.set.call(this,prox(v))}});
  }catch(e){}
});
Element.prototype.setAttribute=function(n,v){
  try{
    var l=String(n).toLowerCase(),t=this.tagName?this.tagName.toLowerCase():"";
    if(l==="integrity")return;
    if(l==="src"||l==="href"||l==="action"||l==="poster"||l==="formaction"||(l==="data"&&t==="object"))v=prox(v);
  }catch(e){}
  return sa.call(this,n,v);
};

// ── リンク/フォーム/履歴/window.open/Navigation API
function fixLink(e){
  var a=e.target&&e.target.closest?e.target.closest("a[href],area[href]"):null;if(!a)return;
  var raw=a.getAttribute("href"),t=prox(raw);if(t!==raw)sa.call(a,"href",t);
}
document.addEventListener("click",fixLink,true);
document.addEventListener("auxclick",fixLink,true);
function fixForm(f){
  try{var a=f.getAttribute("action");if(a){var t=prox(a);if(t!==a)sa.call(f,"action",t)}}catch(e){}
}
document.addEventListener("submit",function(e){if(e.target)fixForm(e.target)},true);
try{var fs=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){fixForm(this);return fs.call(this)}}catch(e){}
["pushState","replaceState"].forEach(function(m){
  var o=history[m];history[m]=function(s,t,u){try{if(u!=null)u=prox(u)}catch(e){}return o.call(this,s,t,u)};
});
try{var wo=window.open;window.open=function(u){var a=[].slice.call(arguments);if(u!=null&&u!=="")a[0]=prox(u);return wo.apply(this,a)}}catch(e){}
try{
  if(window.navigation&&navigation.addEventListener){
    navigation.addEventListener("navigate",function(e){
      try{
        if(!e.cancelable||e.hashChange||e.formData||e.destination.sameDocument)return;
        if(e.navigationType!=="push"&&e.navigationType!=="replace")return;
        var d=e.destination.url,t=prox(d);
        if(t!==d&&new URL(t).href!==new URL(d).href){e.preventDefault();location.assign(t)}
      }catch(x){}
    });
  }
}catch(e){}

// ── ServiceWorker: 自分のSWを登録し、サイト側のSW登録は無効化
try{
  if(navigator.serviceWorker){
    var reg0=navigator.serviceWorker.register.bind(navigator.serviceWorker);
    reg0("/~sw.js",{scope:"/"}).catch(function(){});
    navigator.serviceWorker.register=function(){return Promise.resolve({scope:O+"/",active:null,installing:null,waiting:null,unregister:function(){return Promise.resolve(true)},update:function(){return Promise.resolve()},addEventListener:function(){},removeEventListener:function(){}})};
    navigator.serviceWorker.getRegistrations=function(){return Promise.resolve([])};
  }
}catch(e){}
})();`;
}

// ───────────────────────── ServiceWorker（最終的に全通信を回収） ─────────────────────────
function makeSw() {
  return String.raw`"use strict";
const P=${JSON.stringify(P)},HOSTS=${JSON.stringify(SITE_HOSTS)};
const O=self.location.origin;
const isSite=(h)=>HOSTS.includes(String(h).toLowerCase());
self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("activate",(e)=>e.waitUntil(self.clients.claim()));

function toProxy(u){
  if(u.protocol!=="http:"&&u.protocol!=="https:")return null;
  if(isSite(u.hostname))return O+u.pathname+u.search;
  return O+P+u.protocol.slice(0,-1)+"/"+u.host+u.pathname+u.search;
}
async function clientReal(id){
  if(!id)return null;
  try{
    const c=await self.clients.get(id);if(!c)return null;
    const u=new URL(c.url);if(u.origin!==O)return null;
    const m=/^\/~p\/(https?)\/([^\/]+)/.exec(u.pathname);
    return m?{scheme:m[1],host:m[2]}:null;
  }catch(e){return null}
}
self.addEventListener("fetch",(e)=>{
  const req=e.request;let u;
  try{u=new URL(req.url)}catch(_){return}
  if(req.mode==="navigate")return;
  if(u.origin===O&&(u.pathname.startsWith("/~")))return;
  e.respondWith(handle(e,req,u));
});
async function handle(e,req,u){
  try{
    let target=null;
    if(u.origin===O){
      const c=await clientReal(e.clientId||e.resultingClientId);
      if(c&&!isSite(c.host.replace(/:\d+$/,"")))target=O+P+c.scheme+"/"+c.host+u.pathname+u.search;
    }else{
      target=toProxy(u);
    }
    if(!target)return await fetch(req);
    const init={method:req.method,headers:req.headers,credentials:"same-origin",mode:"same-origin",redirect:req.redirect,
      cache:req.cache==="only-if-cached"?"default":req.cache,referrerPolicy:req.referrerPolicy};
    if(req.referrer&&req.referrer!=="about:client")init.referrer=req.referrer;
    if(req.method!=="GET"&&req.method!=="HEAD")init.body=await req.clone().arrayBuffer();
    return await fetch(new Request(target,init));
  }catch(err){
    try{return await fetch(req)}catch(e2){return new Response("Proxy error",{status:502})}
  }
}`;
}

const SHIM_JS = makeShim();
const SW_JS = makeSw();
SHIM_VER = crypto.createHash("md5").update(SHIM_JS + SW_JS).digest("hex").slice(0, 8);

// ───────────────────────── サーバー起動 ─────────────────────────
const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error("[error]", req.method, req.url, (err && err.message) || err);
    if (!res.headersSent) sendError(req, res, err);
    else res.destroy();
  });
});
server.keepAliveTimeout = 65000; // Renderのロードバランサより長く
server.headersTimeout = 70000;
server.requestTimeout = 0;
server.on("upgrade", handleUpgrade);
server.on("clientError", (err, socket) => {
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});
process.on("uncaughtException", (e) => console.error("[uncaught]", e));
process.on("unhandledRejection", (e) => console.error("[unhandled]", e));
process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
});
server.listen(PORT, () => console.log(`relay listening on ${PORT} -> ${TARGET}`));
