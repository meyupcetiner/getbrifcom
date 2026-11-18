// Yönetici telefonuna anlık bildirim (Web Push, RFC 8291 + VAPID). Dış servis yok; WebCrypto ile.
// parcamnerde'deki sistemin Brif uyarlaması. VAPID anahtar çifti ilk kullanımda üretilir ve D1'de (bildirim_ayar)
// saklanır; Eyüp'ün ayrıca Secret eklemesi gerekmez. Bildirim yalnızca admin'den "bildirimleri aç" diyen cihazlara gider
// ve müşteri adı/telefonu içermez (yalnızca hizmet, bütçe, talep no).

interface D1Stmt { bind(...v: unknown[]): D1Stmt; first<T = any>(): Promise<T | null>; all<T = any>(): Promise<{ results: T[] }>; run(): Promise<unknown> }
interface DB { prepare(q: string): D1Stmt }

const te = new TextEncoder();
const enc64 = (b: ArrayBuffer | Uint8Array) => { let s = ""; const a = new Uint8Array(b); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const dec64 = (s: string) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };
const cat = (...xs: Uint8Array[]) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let i = 0; for (const x of xs) { o.set(x, i); i += x.length; } return o; };

let ready = false;
async function setup(db: DB) {
  if (ready) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS bildirim_cihaz (ep TEXT PRIMARY KEY, sub TEXT NOT NULL, ad TEXT NOT NULL DEFAULT '', c INTEGER NOT NULL)").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS bildirim_ayar (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
  ready = true;
}

let KEYS: { pub: string; priv: JsonWebKey } | null = null;
export async function vapidKeys(db: DB) {
  if (KEYS) return KEYS;
  await setup(db);
  let r = await db.prepare("SELECT v FROM bildirim_ayar WHERE k = 'vapid'").first<{ v: string }>();
  if (!r) {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pub = enc64(await crypto.subtle.exportKey("raw", kp.publicKey) as ArrayBuffer);
    const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    await db.prepare("INSERT OR IGNORE INTO bildirim_ayar (k, v) VALUES ('vapid', ?)").bind(JSON.stringify({ pub, priv })).run();
    r = await db.prepare("SELECT v FROM bildirim_ayar WHERE k = 'vapid'").first<{ v: string }>();
  }
  KEYS = JSON.parse(r!.v);
  return KEYS!;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function vapidAuth(db: DB, endpoint: string) {
  const { pub, priv } = await vapidKeys(db);
  const h = enc64(te.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const c = enc64(te.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://getbrif.com" })));
  const key = await crypto.subtle.importKey("jwk", priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(h + "." + c));
  return `vapid t=${h}.${c}.${enc64(sig)}, k=${pub}`;
}
async function encrypt(sub: { keys: { p256dh: string; auth: string } }, payload: string) {
  const uaPub = dec64(sub.keys.p256dh), auth = dec64(sub.keys.auth);
  const as = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey) as ArrayBuffer);
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey } as any, as.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(te.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, te.encode("Content-Encoding: nonce\0"), 12);
  const k = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, cat(te.encode(payload), new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([asPub.length]), asPub, ct);
}

export async function subscribe(db: DB, s: { endpoint?: string; keys?: { p256dh?: string; auth?: string } }, ad: string) {
  await setup(db);
  if (!s || typeof s.endpoint !== "string" || !/^https:\/\//.test(s.endpoint) || s.endpoint.length > 1000 || !s.keys?.p256dh || !s.keys?.auth) return false;
  await db.prepare("INSERT INTO bildirim_cihaz (ep, sub, ad, c) VALUES (?, ?, ?, ?) ON CONFLICT(ep) DO UPDATE SET sub = excluded.sub, ad = excluded.ad")
    .bind(s.endpoint, JSON.stringify({ endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } }), ad.slice(0, 60), Date.now()).run();
  return true;
}
export async function unsubscribe(db: DB, ep: string) { await setup(db); await db.prepare("DELETE FROM bildirim_cihaz WHERE ep = ?").bind(ep).run(); }
export async function deviceCount(db: DB) { await setup(db); return (await db.prepare("SELECT COUNT(*) AS n FROM bildirim_cihaz").first<{ n: number }>())?.n ?? 0; }

/** Kayıtlı tüm yönetici cihazlarına bildirim gönder. Hata sitenin işleyişini bozmaz. */
export async function sendPush(db: DB, data: { title: string; body: string; url: string; tag?: string }) {
  await setup(db);
  const { results } = await db.prepare("SELECT ep, sub FROM bildirim_cihaz").all<{ ep: string; sub: string }>();
  let sent = 0;
  await Promise.all(results.map(async (r) => {
    try {
      const sub = JSON.parse(r.sub);
      const body = await encrypt(sub, JSON.stringify(data));
      const res = await fetch(sub.endpoint, { method: "POST", headers: { "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "86400", urgency: "high", authorization: await vapidAuth(db, sub.endpoint) }, body });
      if (res.status === 404 || res.status === 410) await db.prepare("DELETE FROM bildirim_cihaz WHERE ep = ?").bind(r.ep).run();
      else if (res.ok) sent++;
      else console.warn("bildirim", res.status, (await res.text()).slice(0, 200));
    } catch (e) { console.warn("bildirim gönderilemedi", (e as Error).message); }
  }));
  return { sent, cihaz: results.length };
}

// Admin sayfasına eklenen istemci kodu ve service worker (CSP: yalnızca 'self' script)
export const BILDIRIM_JS = `(function(){
var box=document.getElementById("bildirim"); if(!box) return;
var st=box.querySelector("[data-durum]"), on=box.querySelector("[data-ac]"), off=box.querySelector("[data-kapat]"), test=box.querySelector("[data-test]");
function say(t){ st.textContent=t; }
function b64(s){ s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4) s+="="; var b=atob(s), a=new Uint8Array(b.length); for(var i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; }
var ios=/iPhone|iPad/.test(navigator.userAgent), standalone=window.navigator.standalone||matchMedia("(display-mode: standalone)").matches;
if(!("serviceWorker" in navigator)||!("PushManager" in window)){ say(ios&&!standalone?"iPhone'da önce bu sayfayı Paylaş → Ana Ekrana Ekle ile ana ekrana ekle, oradan açıp tekrar dene.":"Bu tarayıcı bildirimleri desteklemiyor."); on.hidden=true; return; }
var regP=navigator.serviceWorker.register("/admin/sw.js",{scope:"/admin/"});
function durum(){ regP.then(function(r){ return r.pushManager.getSubscription(); }).then(function(s){ on.hidden=!!s; off.hidden=!s; test.hidden=!s; say(s?"Bu cihazda bildirimler açık.":"Bu cihazda bildirimler kapalı."); }); }
durum();
on.addEventListener("click",function(){ say("İzin isteniyor…");
  Notification.requestPermission().then(function(p){ if(p!=="granted"){ say("İzin verilmedi. Tarayıcı ayarlarından bildirim iznini aç."); return; }
    return Promise.all([regP, fetch("/admin/bildirim/anahtar").then(function(r){return r.json();})]).then(function(x){
      return x[0].pushManager.subscribe({userVisibleOnly:true, applicationServerKey:b64(x[1].key)}); }).then(function(s){
      return fetch("/admin/bildirim/kaydet",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sub:s.toJSON(),ad:(ios?"iPhone":/Android/.test(navigator.userAgent)?"Android":"Bilgisayar")})}); }).then(function(){ durum(); });
  }).catch(function(e){ say("Açılamadı: "+e.message); }); });
off.addEventListener("click",function(){ regP.then(function(r){ return r.pushManager.getSubscription(); }).then(function(s){ if(!s) return; return fetch("/admin/bildirim/sil",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ep:s.endpoint})}).then(function(){ return s.unsubscribe(); }); }).then(durum); });
test.addEventListener("click",function(){ say("Test gönderiliyor…"); fetch("/admin/bildirim/test",{method:"POST"}).then(function(r){return r.json();}).then(function(j){ say(j.sent?"Test bildirimi gönderildi.":"Gönderilemedi; bildirimleri kapatıp yeniden aç."); }); });
})();`;

export const SW_JS = `self.addEventListener("push",function(e){ var d={}; try{ d=e.data.json(); }catch(_){ d={title:"Brif",body:e.data?e.data.text():""}; }
  e.waitUntil(self.registration.showNotification(d.title||"Brif",{body:d.body||"",tag:d.tag||"brif",data:{url:d.url||"/admin"},icon:"/favicon-192.png",badge:"/favicon-48.png"})); });
self.addEventListener("notificationclick",function(e){ e.notification.close(); var u=(e.notification.data&&e.notification.data.url)||"/admin";
  e.waitUntil(clients.matchAll({type:"window",includeUncontrolled:true}).then(function(l){ for(var i=0;i<l.length;i++){ if(l[i].url.indexOf("/admin")>-1){ l[i].navigate(u); return l[i].focus(); } } return clients.openWindow(u); })); });`;

export const MANIFEST = JSON.stringify({ name: "Brif Yönetim", short_name: "Brif", start_url: "/admin/ozet", scope: "/admin/", display: "standalone", background_color: "#ffffff", theme_color: "#191919", icons: [{ src: "/favicon-192.png", sizes: "192x192", type: "image/png" }, { src: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }] });
