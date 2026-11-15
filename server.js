// server.js
// Render上で動くNode.js版の中継サーバー（Cloudflare Workers版 worker.js と同じ処理）
import http from "node:http";
import { Readable } from "node:stream";

// ↓ 中継したいサイトのURL（環境変数 TARGET で上書き可能）
const TARGET = process.env.TARGET || "https://www.tiktok.com";
const BASE = new URL(TARGET);
const BARE = BASE.hostname.replace(/^www\./i, "");
const SITE_HOSTS = [BARE, "www." + BARE];
const isSiteHost = (h) => SITE_HOSTS.includes(String(h).toLowerCase());

// <a> <area> <form> の href/action
const LINK_RE = /(<(?:a|area|form)\b[^>]*?\s(?:href|action)\s*=\s*)(["'])(.*?)\2/gi;
// 画像・JS・CSSなどのリソース
const RES_RE = /(<(?:script|img|source|video|audio|link|iframe|input)\b[^>]*?\s(?:src|href)\s*=\s*)(["'])(.*?)\2/gi;

// 中継先のリンクを自分のサーバーのURLへ
function rewriteLinks(html, upstream, myOrigin) {
  return html.replace(LINK_RE, (m, pre, q, val) => {
    const v = val.trim();
    if (/^(#|javascript:|mailto:|tel:|data:)/i.test(v)) return m;
    let abs;
    try {
      abs = new URL(v, upstream);
    } catch {
      return m;
    }
    if (!isSiteHost(abs.host)) return m;
    return pre + q + myOrigin + abs.pathname + abs.search + abs.hash + q;
  });
}

// リソースのURLを絶対URLにする
function rewriteResources(html, upstream) {
  return html.replace(RES_RE, (m, pre, q, val) => {
    const v = val.trim();
    if (!v || /^(data:|blob:|javascript:)/i.test(v)) return m;
    let abs;
    try {
      abs = new URL(v, upstream);
    } catch {
      return m;
    }
    if (!/^https?:$/.test(abs.protocol)) return m;
    return pre + q + abs.href + q;
  });
}

// ブラウザ側の補正スクリプト
function makeShim() {
  return `<script>(function(){
var HOSTS=${JSON.stringify(SITE_HOSTS)},O=location.origin,SITE=${JSON.stringify(BASE.origin)};
function isSite(h){return HOSTS.indexOf(String(h).toLowerCase())>=0}
function local(h){
  try{
    var u=new URL(h,location.href);
    if(u.origin===O) return u.href;
    if(isSite(u.host)) return O+u.pathname+u.search+u.hash;
    return u.href;
  }catch(e){return h}
}
function upstream(h){
  try{
    var u=new URL(h,location.href);
    if(u.origin===O||isSite(u.host)) return SITE+u.pathname+u.search+u.hash;
    return u.href;
  }catch(e){return h}
}
document.addEventListener("click",function(e){
  var a=e.target&&e.target.closest?e.target.closest("a[href],area[href]"):null;
  if(!a||a.target==="_blank") return;
  if(e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey) return;
  var t=local(a.href);
  if(t.indexOf(O)!==0) return;
  e.preventDefault();
  location.assign(t);
},true);
document.addEventListener("submit",function(e){
  var f=e.target;
  if(!f||!f.action) return;
  var t=local(f.action);
  if(t.indexOf(O)===0) f.action=t;
},true);
var ps=history.pushState, rs=history.replaceState;
history.pushState=function(s,t,u){if(u!=null)u=local(String(u));return ps.call(this,s,t,u)};
history.replaceState=function(s,t,u){if(u!=null)u=local(String(u));return rs.call(this,s,t,u)};
var f0=window.fetch;
window.fetch=function(i,o){
  var url=(typeof i==="string"||i instanceof URL)?upstream(String(i)):new Request(upstream(i.url),i);
  return f0.call(this,url,o);
};
var X=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  var a=[].slice.call(arguments);a[1]=upstream(String(u));return X.apply(this,a);
};
})();</script>`;
}

async function handle(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "content-type": "text/plain" });
    return res.end("Method Not Allowed");
  }

  // 自分のOrigin（Render等のリバースプロキシ越しでも正しく組み立てる）
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const myOrigin = `${proto}://${host}`;
  const url = new URL(req.url, myOrigin);

  // 自分のパスを中継先の同じパスに対応させる
  const upstream = new URL(url.pathname + url.search, BASE.origin);

  const upRes = await fetch(upstream, {
    headers: {
      "User-Agent": req.headers["user-agent"] ?? "",
      "Accept-Language": req.headers["accept-language"] ?? "",
      "Accept": req.headers["accept"] ?? "*/*",
    },
    redirect: "manual",
  });

  // リダイレクト：中継先のホストなら自分のURLに置き換える
  const loc = upRes.headers.get("location");
  if (loc && upRes.status >= 300 && upRes.status < 400) {
    const l = new URL(loc, upstream);
    const dest = isSiteHost(l.host)
      ? myOrigin + l.pathname + l.search + l.hash
      : l.href;
    res.writeHead(302, { location: dest });
    return res.end();
  }

  // HTML以外はそのまま返す（ストリーム転送）
  const type = upRes.headers.get("content-type") || "application/octet-stream";
  if (!/text\/html/i.test(type)) {
    res.writeHead(upRes.status, {
      "content-type": type,
      "cache-control": "no-store",
    });
    if (req.method === "HEAD" || !upRes.body) return res.end();
    return Readable.fromWeb(upRes.body).pipe(res);
  }

  let html = await upRes.text();
  html = rewriteLinks(html, upstream, myOrigin);
  html = rewriteResources(html, upstream);

  const shim = makeShim();
  html = /<head[^>]*>/i.test(html)
    ? html.replace(/<head[^>]*>/i, (m) => m + shim)
    : shim + html;

  res.writeHead(upRes.status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(req.method === "HEAD" ? undefined : html);
}

const PORT = process.env.PORT || 10000; // Renderは PORT 環境変数を渡す
http
  .createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end("Bad Gateway");
    });
  })
  .listen(PORT, () => console.log(`relay listening on ${PORT} -> ${TARGET}`));
