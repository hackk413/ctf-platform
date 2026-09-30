import { getCookie, readToken, harden, clearCookie } from '../lib/auth.mjs';
import { portalHtml, portalCss, portalJs } from '../lib/assets.mjs';
function denied(res){Object.entries(harden({'content-type':'text/plain; charset=utf-8'})).forEach(([k,v])=>res.setHeader(k,v));return res.status(302).setHeader('location','/').end();}
export default function handler(req,res){
  const {SESSION_SECRET}=process.env;const data=readToken(getCookie(req,'ctf_atlas_session'),SESSION_SECRET||'');if(!data)return denied(res);
  let html=portalHtml.replace('<link rel="stylesheet" href="styles.css">','<style>'+portalCss.replaceAll('</style','<\/style')+'</style>').replace('<script src="app.js"></script>','<script>'+portalJs.replaceAll('</script','<\/script')+'</script>');
  // Keep the protected portal standalone: its learning content and client logic are in this authenticated response.
  html=html.replace('<title>CTF Atlas // Secure Learning Range</title>','<title>CTF ATLAS // AUTHENTICATED RANGE</title>');
  Object.entries(harden({'content-type':'text/html; charset=utf-8'})).forEach(([k,v])=>res.setHeader(k,v));
  return res.status(200).send(html);
}
