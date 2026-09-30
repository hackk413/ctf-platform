import { clearCookie, harden } from '../lib/auth.mjs';
export default function handler(req,res){if(req.method!=='POST')return res.status(405).setHeader('allow','POST').end();Object.entries(harden({'set-cookie':clearCookie(),'content-type':'application/json; charset=utf-8'})).forEach(([k,v])=>res.setHeader(k,v));return res.status(200).json({ok:true});}
