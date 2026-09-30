import crypto from 'node:crypto';
export const COOKIE='ctf_atlas_session';
export const TTL=60*60*12;
export function getCookie(req,name){const raw=req.headers.cookie||'';for(const piece of raw.split(';')){const [k,...rest]=piece.trim().split('=');if(k===name)return rest.join('=')}return null}
export function makeToken(uid,secret){const payload=Buffer.from(JSON.stringify({uid,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+TTL})).toString('base64url');const sig=crypto.createHmac('sha256',secret).update(payload).digest('base64url');return payload+'.'+sig}
export function readToken(token,secret){try{const [payload,sig]=String(token||'').split('.');if(!payload||!sig)return null;const expected=crypto.createHmac('sha256',secret).update(payload).digest();const got=Buffer.from(sig,'base64url');if(got.length!==expected.length||!crypto.timingSafeEqual(got,expected))return null;const data=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));if(!data.exp||data.exp<Math.floor(Date.now()/1000))return null;return data}catch{return null}}
export function sessionCookie(token){return `${COOKIE}=${token}; Max-Age=${TTL}; Path=/; HttpOnly; Secure; SameSite=Strict`}
export function clearCookie(){return `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`}
export function harden(headers={}){return {'cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'no-referrer','permissions-policy':'camera=(), microphone=(), geolocation=()',...headers}}
