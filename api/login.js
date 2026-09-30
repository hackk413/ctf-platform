import { makeToken, sessionCookie, harden } from '../lib/auth.mjs';
export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).setHeader('allow','POST').json({ok:false});
  const {ATLAS_UID,ATLAS_PASSWORD,SESSION_SECRET}=process.env;
  if(!ATLAS_UID||!ATLAS_PASSWORD||!SESSION_SECRET) return res.status(503).json({ok:false,error:'Authentication is not configured'});
  const uid=String(req.body?.uid||''); const password=String(req.body?.password||'');
  if(uid!==ATLAS_UID||password!==ATLAS_PASSWORD) return res.status(401).setHeader('cache-control','no-store').json({ok:false,error:'Invalid credentials'});
  const token=makeToken(uid,SESSION_SECRET);
  Object.entries(harden({'set-cookie':sessionCookie(token),'content-type':'application/json; charset=utf-8'})).forEach(([k,v])=>res.setHeader(k,v));
  return res.status(200).json({ok:true});
}
