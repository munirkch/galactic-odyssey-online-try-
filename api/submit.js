import { ok, bad, cors, sha256, nowSec, insertScore, countRecentByIp, verifyIssuedToken } from "./_lib.js";

const reName = /^[A-Za-z0-9_\- ]{1,16}$/;
const badWords = [/fuck/i, /shit/i, /bitch/i];

export default async function handler(req){
  const origin = cors();
  if(req.method === 'OPTIONS') return ok({}, origin);
  if(req.method !== 'POST') return bad(405, 'Method not allowed', origin);

  const ip = (req.headers.get?.('x-forwarded-for') || req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip_hash = sha256(`${ip}:${process.env.HS_PEPPER||'pepper'}`);

  let body; try { body = await req.json?.() ?? {}; } catch { return bad(400, 'Invalid JSON', origin); }
  const { username, score, ts, sig, fingerprint } = body;

  if(!Number.isFinite(score) || score<0) return bad(400, 'Invalid score', origin);
  if(!reName.test(username||'')) return bad(400, 'Invalid username', origin);
  if(badWords.some(rx => rx.test(username))) return bad(400, 'Profanity not allowed', origin);
  if(!ts || !sig) return bad(400, 'Missing token', origin);

  // sig must be "<token>|<clientTs>"
  const [token, clientTsStr] = String(sig).split("|");
  if(!token || !clientTsStr) return bad(401, 'Malformed sig', origin);
  if(!verifyIssuedToken(token)) return bad(401, 'Invalid token', origin);
  const clientTs = parseInt(clientTsStr,10);
  if(!Number.isFinite(clientTs) || Math.abs(nowSec() - clientTs) > 15*60) return bad(401, 'Clock skew', origin);

  // rate limit (per minute)
  const recent = await countRecentByIp(ip_hash);
  const limit = parseInt(process.env.RATE_PER_MIN||'10',10);
  if(recent >= limit) return bad(429, 'Rate limited', origin);

  if(score > 2_000_000_000) return bad(400, 'Score too large', origin);

  await insertScore({ username, score, fingerprint: fingerprint||null, ip_hash });
  return ok({ ok: true }, origin);
}
