import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT=process.cwd();
const OUT=path.join(ROOT,'data','live-intel.json');
const UA='CTF-Atlas-Intelligence/1.0 (+https://github.com/ctf-atlas)';
const now=new Date();

const sources=[
  {id:'cisa-kev', name:'CISA Known Exploited Vulnerabilities', type:'kev', url:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'},
  {id:'nvd', name:'NVD CVE API', type:'nvd', url:'https://services.nvd.nist.gov/rest/json/cves/2.0'},
  {id:'owasp-top10', name:'OWASP Top 10 repository', type:'github-atom', url:'https://github.com/OWASP/Top10/releases.atom'},
  {id:'juice-shop', name:'OWASP Juice Shop releases', type:'github-atom', url:'https://github.com/OWASP/juice-shop/releases.atom'},
  {id:'pwntools', name:'pwntools releases', type:'github-atom', url:'https://github.com/Gallopsled/pwntools/releases.atom'}
];

const taxonomy=[
  ['web','web security','web, http, api, csrf, xss, ssrf, injection, authentication, authorization, browser, oauth, jwt, cors'],
  ['crypto','cryptography','crypto, cipher, rsa, ecc, aes, des, hash, hashing, hmac, signature, nonce, random'],
  ['binary','binary exploitation','buffer overflow, rop, ret2libc, format string, heap, elf, assembly, gdb, pwntools'],
  ['reverse','reverse engineering','reverse engineering, ghidra, ida, debugger, assembly, decompiler, obfuscation'],
  ['forensics','digital forensics','forensics, pcap, wireshark, memory, disk, artifact, timeline, evtx'],
  ['osint','osint','osint, reconnaissance, domain, dns, metadata, search, public information'],
  ['cloud','cloud and containers','cloud, kubernetes, docker, container, iam, metadata service, workload identity'],
  ['supply-chain','software supply chain','dependency, package, ci/cd, supply chain, sbom, build, signing'],
  ['identity','identity and access','identity, authentication, authorization, kerberos, ldap, sso, oauth, saml'],
  ['blue-team','detection and response','detection, logging, alert, siem, yara, sigma, incident response, hunting']
];

function normalize(s=''){return s.toLowerCase().replace(/\s+/g,' ').trim();}
function stripHtml(s=''){return s.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&#39;/g,"'").replace(/&quot;/g,'"').replace(/&#x27;/g,"'").replace(/\s+/g,' ').trim();}
function isoOrNull(x){const d=new Date(x); return Number.isNaN(d.valueOf())?null:d.toISOString();}
async function fetchText(url,timeout=30000){const c=new AbortController();const t=setTimeout(()=>c.abort(),timeout);try{const r=await fetch(url,{headers:{'user-agent':UA,'accept':'application/json, application/xml, text/xml, text/plain, text/html;q=0.9, */*;q=0.8'},signal:c.signal});if(!r.ok)throw new Error(`${r.status} ${r.statusText}`);return await r.text();}finally{clearTimeout(t)}}
function topicFor(text){const n=normalize(text);const scored=taxonomy.map(([id,label,keys])=>{const score=keys.split(', ').reduce((a,k)=>a+(n.includes(k)?1:0),0);return {id,label,score}}).sort((a,b)=>b.score-a.score);return scored[0].score?scored[0]:{id:'general',label:'general security',score:0};}

async function readKev(src){
  const j=JSON.parse(await fetchText(src.url));
  const vulns=Array.isArray(j.vulnerabilities)?j.vulnerabilities:[];
  const recent=vulns.filter(v=>{const d=new Date(v.dateAdded||v.dateLastModified||0);return now-d<1000*60*60*24*45}).sort((a,b)=>new Date(b.dateAdded||0)-new Date(a.dateAdded||0)).slice(0,20);
  return recent.map(v=>{const topic=topicFor(`${v.vulnerabilityName} ${v.shortDescription||''} ${v.product||''}`);return {id:`kev:${v.cveID}`,kind:'KEV',title:v.vulnerabilityName||v.cveID,summary:v.shortDescription||'CISA added this vulnerability to its Known Exploited Vulnerabilities catalog.',date:isoOrNull(v.dateAdded),severity:'exploited',topic:topic.label,source:src.name,sourceUrl:src.url,cve:v.cveID,product:v.product||''};});
}

async function readNvd(src){
  const end=new Date(); const start=new Date(end.getTime()-1000*60*60*24*3);
  const url=`${src.url}?lastModStartDate=${encodeURIComponent(start.toISOString())}&lastModEndDate=${encodeURIComponent(end.toISOString())}&resultsPerPage=40`;
  const j=JSON.parse(await fetchText(url));
  const vulns=Array.isArray(j.vulnerabilities)?j.vulnerabilities:[];
  return vulns.slice(0,40).map(w=>{const v=w.cve||{};const desc=(v.descriptions||[]).find(x=>x.lang==='en')?.value||'';const topic=topicFor(`${v.id} ${v.sourceIdentifier||''} ${desc}`);const cvss=v.metrics?.cvssMetricV31?.[0]?.cvssData||v.metrics?.cvssMetricV30?.[0]?.cvssData||v.metrics?.cvssMetricV2?.[0]?.cvssData||{};return {id:`cve:${v.id}`,kind:'CVE',title:v.id,summary:desc.slice(0,380),date:isoOrNull(v.published||v.lastModified),severity:cvss.baseSeverity||'unknown',topic:topic.label,source:src.name,sourceUrl:`https://nvd.nist.gov/vuln/detail/${v.id}`,cve:v.id,score:cvss.baseScore??null};});
}

function parseAtom(xml,src){
  const entries=[...xml.matchAll(/<entry[\s\S]*?<\/entry>/gi)].map(m=>m[0]);
  return entries.slice(0,15).map(e=>{
    const text=(tag)=>{const m=e.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?stripHtml(m[1]):''};
    const linkm=e.match(/<link[^>]+href=["']([^"']+)["']/i);
    const title=text('title'); const summary=text('summary')||text('content'); const date=isoOrNull(text('updated')||text('published')); const url=linkm?.[1]||src.url; const topic=topicFor(`${title} ${summary}`);
    return {id:`release:${src.id}:${date||title}`,kind:'RELEASE',title,summary:summary.slice(0,380),date,severity:'info',topic:topic.label,source:src.name,sourceUrl:url};
  });
}

async function readAtom(src){return parseAtom(await fetchText(src.url),src)}
async function readSource(src){if(src.type==='kev')return readKev(src);if(src.type==='nvd')return readNvd(src);if(src.type==='github-atom')return readAtom(src);throw new Error('unknown source type');}

const items=[];const sourceStatus=[];
for(const src of sources){
  try{const rows=await readSource(src);items.push(...rows);sourceStatus.push({id:src.id,name:src.name,status:'ok',count:rows.length,url:src.url});}
  catch(err){sourceStatus.push({id:src.id,name:src.name,status:'error',count:0,url:src.url,error:String(err?.message||err).slice(0,180)});}
}

items.sort((a,b)=>new Date(b.date||0)-new Date(a.date||0));
const unique=[];const seen=new Set();for(const x of items){if(seen.has(x.id))continue;seen.add(x.id);unique.push(x)}
const topicMap=new Map();for(const x of unique){if(!x.topic)continue;const k=x.topic;topicMap.set(k,(topicMap.get(k)||0)+1)}
const topicSignals=[...topicMap.entries()].sort((a,b)=>b[1]-a[1]).slice(0,12).map(([topic,count])=>({topic,count,reason:`Recent source activity is clustering around ${topic}. Review the affected concept area, then add or deepen a lab rather than copying the advisory verbatim.`}));
const out={
  updatedAt:now.toISOString(),status:sourceStatus.some(s=>s.status==='error')?'partial':'ok',
  summary:{vulnerabilities:unique.filter(x=>x.kind==='CVE').length,kev:unique.filter(x=>x.kind==='KEV').length,releases:unique.filter(x=>x.kind==='RELEASE').length,signals:unique.length},
  items:unique.slice(0,90),topicSignals,
  sources:sourceStatus,
  notes:[
    'Signals are collected from a curated allowlist of security data sources and normalized locally.',
    'The updater is discovery-first: it suggests topics and freshness work; it does not silently rewrite core lessons or ingest untrusted executable content.',
    'Automated summaries are intentionally bounded so the site remains readable. Deep curriculum changes should be reviewed before publication.'
  ]
};
await fs.writeFile(OUT,JSON.stringify(out,null,2)+'\n');
console.log(`wrote ${unique.length} signals -> ${OUT}`);
console.table(sourceStatus.map(s=>({source:s.id,status:s.status,count:s.count})));
