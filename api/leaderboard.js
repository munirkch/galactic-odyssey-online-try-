import { ok, bad, cors, queryTop } from "./_lib.js";

export default async function handler(req){
  const origin = cors();
  if(req.method === 'OPTIONS') return ok({}, origin);
  if(req.method !== 'GET') return bad(405,'Method not allowed', origin);
  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get('limit')||'100',10);
  const since = url.searchParams.get('since');
  const sinceDays = since && since.endsWith('d') ? parseInt(since.slice(0,-1),10) : null;
  try{
    const data = await queryTop(limit, sinceDays);
    return ok(data, origin);
  }catch(e){
    return bad(500, 'DB error', origin);
  }
}
