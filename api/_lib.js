import crypto from "node:crypto";

export const ok = (data, origin) => new Response(JSON.stringify(data), {
  status: 200,
  headers: {
    "content-type": "application/json",
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type"
  }
});
export const bad = (code, msg, origin) => new Response(JSON.stringify({ error: msg }), {
  status: code,
  headers: { "content-type": "application/json", "access-control-allow-origin": origin }
});
export const cors = () => (process.env.CORS_ORIGIN || "*");
export const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
export const hmac = (secret, s) => crypto.createHmac("sha256", secret).update(s).digest("hex");
export const nowSec = () => Math.floor(Date.now()/1000);

export function verifyIssuedToken(token) {
  // token format: "<ts>.<exp>.<sig>"
  if(!token || typeof token!=="string") return false;
  const parts = token.split(".");
  if(parts.length !== 3) return false;
  const [tsStr, expStr, sig] = parts;
  if(!/^\d+$/.test(tsStr) || !/^\d+$/.test(expStr)) return false;
  const mac = hmac(process.env.HMAC_SECRET, `${tsStr}.${expStr}`);
  if(mac !== sig) return false;
  const now = nowSec();
  if(now > parseInt(expStr,10)) return false;
  return true;
}

export async function insertScore(row){
  const { username, score, fingerprint, ip_hash } = row;
  const res = await fetch(`${process.env.SUPABASE_URL}/rest/v1/scores`, {
    method: 'POST',
    headers: {
      'apikey': process.env.SUPABASE_SERVICE_ROLE,
      'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    },
    body: JSON.stringify([{ username, score, fingerprint, ip_hash }])
  });
  if(!res.ok){ throw new Error(`DB insert failed: ${res.status}`); }
  return res.json();
}

export async function queryTop(limit=100, sinceDays=null){
  const url = new URL(`${process.env.SUPABASE_URL}/rest/v1/scores`);
  url.searchParams.set('select', 'username,score,created_at');
  url.searchParams.set('order', 'score.desc,created_at.desc');
  url.searchParams.set('limit', String(Math.min(1000, limit)));
  if(sinceDays){
    const since = new Date(Date.now() - sinceDays*86400*1000).toISOString();
    url.searchParams.set('created_at', `gte.${since}`);
  }
  const res = await fetch(url, {
    headers: { 'apikey': process.env.SUPABASE_SERVICE_ROLE, 'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE}` }
  });
  if(!res.ok) throw new Error(`DB query failed: ${res.status}`);
  const items = await res.json();
  return { items, total: items.length };
}

export async function countRecentByIp(ip_hash){
  const sinceIso = new Date(Date.now() - 60*1000).toISOString();
  const url = new URL(`${process.env.SUPABASE_URL}/rest/v1/scores`);
  url.searchParams.set('select', 'id');
  url.searchParams.set('ip_hash', `eq.${ip_hash}`);
  url.searchParams.set('created_at', `gte.${sinceIso}`);
  const res = await fetch(url, { headers: { 'apikey': process.env.SUPABASE_SERVICE_ROLE, 'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE}` } });
  if(!res.ok) return 0; const arr = await res.json(); return arr.length|0;
}
