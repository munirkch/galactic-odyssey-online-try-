import { ok, bad, cors, nowSec, hmac } from "./_lib.js";

export default async function handler(req){
  const origin = cors();
  if(req.method === 'OPTIONS') return ok({}, origin);
  if(req.method !== 'GET') return bad(405, 'Method not allowed', origin);
  const ts = nowSec();
  const exp = ts + 15*60;
  const payload = `${ts}.${exp}`;
  const sig = hmac(process.env.HMAC_SECRET, payload);
  return ok({ token: `${payload}.${sig}`, expiresAt: exp }, origin);
}
