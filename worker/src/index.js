// خادم صور موقع علي زغير — Cloudflare Worker
// الصور تنحفظ بـ KV (GALLERY). الدخول بإيميل الدكتور + كلمة سر (ADMIN_PASSWORD سر بلوحة Cloudflare).
const MAX_BYTES = 3 * 1024 * 1024;
const MAX_IMAGES = 60;
const TOKEN_DAYS = 14;
const TYPES = ["image/webp", "image/jpeg", "image/png"];

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function hmac(env, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode("zg:" + env.ADMIN_PASSWORD), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
async function sha(s) { return b64u(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function safeEq(a, b) { const [x, y] = await Promise.all([sha(a), sha(b)]); return x === y; }

async function makeToken(env) {
  const exp = Date.now() + TOKEN_DAYS * 864e5;
  return exp + "." + (await hmac(env, String(exp)));
}
async function checkToken(env, req) {
  const t = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, await hmac(env, exp));
}

function cors(env, req) {
  const o = req.headers.get("Origin");
  return o && o === env.SITE_ORIGIN ? { "Access-Control-Allow-Origin": o, "Vary": "Origin" } : {};
}
const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });

async function getList(env) { return (await env.GALLERY.get("list", "json")) || []; }

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    const c = cors(env, req);

    if (req.method === "OPTIONS") return new Response(null, { headers: { ...c, "Access-Control-Allow-Methods": "GET", "Access-Control-Max-Age": "86400" } });
    if (!env.ADMIN_PASSWORD && p.startsWith("/api/") && p !== "/api/gallery") return json({ error: "not_configured" }, 503);

    // عام: قائمة الصور للموقع
    if (p === "/api/gallery" && req.method === "GET") {
      const list = await getList(env);
      return json(list.map(({ id, caption }) => ({ id, caption, src: url.origin + "/img/" + id })), 200, { ...c, "Cache-Control": "public, max-age=60" });
    }
    // عام: الصورة نفسها
    if (p.startsWith("/img/") && req.method === "GET") {
      const id = p.slice(5);
      if (!/^[a-z0-9]{8,32}$/.test(id)) return new Response("Not found", { status: 404 });
      const { value, metadata } = await env.GALLERY.getWithMetadata("img:" + id, "arrayBuffer");
      if (!value) return new Response("Not found", { status: 404 });
      return new Response(value, { headers: { "Content-Type": metadata?.type || "image/webp", "Cache-Control": "public, max-age=31536000, immutable" } });
    }
    // لوحة التعديل (مخفية: ماكو رابط لها بالموقع)
    if (p === "/admin" && req.method === "GET") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex, nofollow", "Cache-Control": "no-store", "X-Frame-Options": "DENY" } });
    }
    // الدخول
    if (p === "/api/login" && req.method === "POST") {
      const ip = req.headers.get("CF-Connecting-IP") || "x";
      const fk = "fail:" + ip;
      const fails = Number(await env.GALLERY.get(fk)) || 0;
      if (fails >= 5) return json({ error: "too_many" }, 429);
      let b = {};
      try { b = await req.json(); } catch {}
      const okEmail = String(b.email || "").trim().toLowerCase() === String(env.ADMIN_EMAIL).toLowerCase();
      const okPass = await safeEq(String(b.password || ""), env.ADMIN_PASSWORD);
      if (!(okEmail && okPass)) {
        await env.GALLERY.put(fk, String(fails + 1), { expirationTtl: 900 });
        return json({ error: "wrong" }, 401);
      }
      return json({ token: await makeToken(env) });
    }
    // باقي العمليات تحتاج دخول
    if (p.startsWith("/api/")) {
      if (!(await checkToken(env, req))) return json({ error: "auth" }, 401);

      if (p === "/api/list" && req.method === "GET") {
        const list = await getList(env);
        return json(list.map(({ id, caption }) => ({ id, caption, src: url.origin + "/img/" + id })));
      }
      if (p === "/api/upload" && req.method === "POST") {
        const type = (req.headers.get("Content-Type") || "").split(";")[0];
        if (!TYPES.includes(type)) return json({ error: "type" }, 415);
        const buf = await req.arrayBuffer();
        if (!buf.byteLength || buf.byteLength > MAX_BYTES) return json({ error: "size" }, 413);
        const list = await getList(env);
        if (list.length >= MAX_IMAGES) return json({ error: "full" }, 409);
        const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
        let caption = "";
        try { caption = decodeURIComponent(req.headers.get("X-Caption") || "").slice(0, 120); } catch {}
        await env.GALLERY.put("img:" + id, buf, { metadata: { type } });
        list.unshift({ id, caption, t: Date.now() });
        await env.GALLERY.put("list", JSON.stringify(list));
        return json({ ok: true, id });
      }
      if (p.startsWith("/api/img/") && req.method === "DELETE") {
        const id = p.slice(9);
        const list = await getList(env);
        const next = list.filter((x) => x.id !== id);
        if (next.length === list.length) return json({ error: "not_found" }, 404);
        await env.GALLERY.put("list", JSON.stringify(next));
        await env.GALLERY.delete("img:" + id);
        return json({ ok: true });
      }
      return json({ error: "not_found" }, 404);
    }
    return new Response("Not found", { status: 404 });
  },
};

const ADMIN_HTML = `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>لوحة الصور | علي زغير</title>
<style>
:root{--t:#0E7C86;--td:#0b4f57;--h:#FF7A59;--mu:#5b6b6e}
*{box-sizing:border-box}body{margin:0;font-family:Tahoma,"Segoe UI",sans-serif;color:#17313a;line-height:1.8;background:radial-gradient(520px 420px at 85% 4%,#bfe6e6,transparent 70%),radial-gradient(480px 400px at 8% 90%,#ffd9cc,transparent 70%),#f6fbfb;min-height:100vh}
.w{max-width:760px;margin:0 auto;padding:20px 16px 60px}h1{color:var(--td);font-size:24px;margin:6px 0 16px}
.box{background:#ffffffb8;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border:1px solid #fff;border-radius:20px;padding:18px;box-shadow:0 10px 30px #0e7c8622;margin-bottom:16px}
label{display:block;font-weight:700;color:var(--td);margin:8px 0 4px}
input{width:100%;min-height:48px;padding:10px 14px;border:1.5px solid #cfe3e3;border-radius:14px;font:inherit;background:#fff}
button{min-height:48px;border:0;border-radius:999px;padding:10px 22px;font:inherit;font-weight:700;cursor:pointer;background:var(--t);color:#fff}
button.del{background:#fff;color:#c0392b;border:1.5px solid #f2c4bd;min-height:40px;padding:6px 14px;width:100%}
button.ghost{background:#fff;color:var(--td);border:1.5px solid var(--t)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.it{background:#fff;border-radius:16px;padding:8px;border:1px solid #e3eeee}.it img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:12px;display:block}
.it p{margin:6px 0;font-size:13px;color:var(--mu);min-height:20px}
.msg{min-height:24px;font-size:14px;color:var(--mu)}.err{color:#c0392b}.hide{display:none}
:focus-visible{outline:3px solid var(--h);outline-offset:2px}
</style></head><body><div class="w">
<h1>لوحة صور الموقع</h1>
<div id="login" class="box"><label for="em">الإيميل</label><input id="em" type="email" autocomplete="username" dir="ltr">
<label for="pw">كلمة السر</label><input id="pw" type="password" autocomplete="current-password" dir="ltr">
<div class="row"><button id="go">دخول</button></div><p class="msg" id="lm" role="status"></p></div>
<div id="app" class="hide">
<div class="box"><label for="f">أضف صور جديدة</label><input id="f" type="file" accept="image/*" multiple>
<label for="cap">وصف قصير (اختياري)</label><input id="cap" type="text" maxlength="120" placeholder="مثال: جلسة تأهيل ركبة">
<div class="row"><button id="up">ارفع الصور</button><button class="ghost" id="out">خروج</button></div><p class="msg" id="um" role="status"></p></div>
<div class="box"><h2 style="margin:0 0 10px;color:var(--td);font-size:19px">الصور الموجودة بالموقع</h2><div class="g" id="grid"></div><p class="msg" id="gm"></p></div>
</div></div>
<script>
var T=null;try{T=sessionStorage.getItem("zg_t")}catch(e){}
var $=function(i){return document.getElementById(i)};
function api(p,o){o=o||{};o.headers=o.headers||{};if(T)o.headers.Authorization="Bearer "+T;return fetch(p,o)}
function show(){ $("login").classList.add("hide");$("app").classList.remove("hide");load()}
function msg(id,t,bad){var m=$(id);m.textContent=t;m.className="msg"+(bad?" err":"")}
$("go").onclick=function(){msg("lm","جاري الدخول...");fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:$("em").value,password:$("pw").value})}).then(function(r){return r.json().then(function(j){return{s:r.status,j:j}})}).then(function(x){if(x.j.token){T=x.j.token;try{sessionStorage.setItem("zg_t",T)}catch(e){}show()}else msg("lm",x.s==429?"محاولات كثيرة، جرب بعد ربع ساعة.":"الإيميل أو كلمة السر غلط.",true)}).catch(function(){msg("lm","ماكو اتصال، جرب مرة ثانية.",true)})};
$("out").onclick=function(){T=null;try{sessionStorage.removeItem("zg_t")}catch(e){}location.reload()};
function load(){api("/api/list").then(function(r){if(r.status==401){$("out").onclick();return null}return r.json()}).then(function(l){if(!l)return;var g=$("grid");g.innerHTML="";if(!l.length)msg("gm","ماكو صور بعد. أضف أول صورة من فوق.");else msg("gm",l.length+" صورة");
l.forEach(function(x){var d=document.createElement("div");d.className="it";var im=document.createElement("img");im.src=x.src;im.alt=x.caption||"صورة";im.loading="lazy";var p=document.createElement("p");p.textContent=x.caption||"";var b=document.createElement("button");b.className="del";b.textContent="امسح";
b.onclick=function(){if(b.dataset.c!=="1"){b.dataset.c="1";b.textContent="متأكد؟ اضغط مرة ثانية";return}b.disabled=true;api("/api/img/"+x.id,{method:"DELETE"}).then(load)};d.append(im,p,b);g.append(d)})})}
function shrink(file){return new Promise(function(res,rej){var img=new Image();img.onload=function(){var M=1600,w=img.width,h=img.height,s=Math.min(1,M/Math.max(w,h));var c=document.createElement("canvas");c.width=Math.round(w*s);c.height=Math.round(h*s);c.getContext("2d").drawImage(img,0,0,c.width,c.height);URL.revokeObjectURL(img.src);c.toBlob(function(b){b?res(b):rej()},"image/jpeg",.82)};img.onerror=rej;img.src=URL.createObjectURL(file)})}
$("up").onclick=async function(){var fs=$("f").files;if(!fs.length){msg("um","اختار صورة أول.",true);return}$("up").disabled=true;var ok=0;
for(var i=0;i<fs.length;i++){msg("um","جاري رفع "+(i+1)+" من "+fs.length+"...");try{var b=await shrink(fs[i]);var r=await api("/api/upload",{method:"POST",headers:{"Content-Type":b.type||"image/jpeg","X-Caption":encodeURIComponent($("cap").value||"")},body:b});if(r.ok)ok++;else if(r.status==409){msg("um","وصلت الحد (60 صورة). امسح صور قديمة أول.",true);break}}catch(e){}}
$("up").disabled=false;$("f").value="";$("cap").value="";msg("um","انرفعت "+ok+" صورة. تبين بالموقع خلال دقيقة.");load()};
if(T)show();
</script></body></html>`;
