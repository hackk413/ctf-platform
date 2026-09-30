import fs from 'node:fs';
import { getCookie, readToken, harden } from '../lib/auth.mjs';

function loadIntel(){
  try {
    return JSON.parse(fs.readFileSync(new URL('../data/live-intel.json', import.meta.url), 'utf8'));
  } catch {
    return { updatedAt:null, status:'unavailable', summary:{vulnerabilities:0,kev:0,releases:0,signals:0}, items:[], topicSignals:[], sources:[], notes:['No intelligence snapshot is available yet.'] };
  }
}

export default function handler(req,res){
  const secret=process.env.SESSION_SECRET||'';
  const session=readToken(getCookie(req,'ctf_atlas_session'),secret);
  const headers=harden({'content-type':'application/json; charset=utf-8'});
  Object.entries(headers).forEach(([k,v])=>res.setHeader(k,v));
  if(!session) return res.status(401).json({ok:false,error:'Authentication required'});
  return res.status(200).json({ok:true,data:loadIntel()});
}
