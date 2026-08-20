// COLINSKIS CARD VAULT V8 — Cloudflare Worker
// Secrets required:
// GH_TOKEN = GitHub token with Contents write access to ColinNr1/Colinskis-Cards
// SESSION_SECRET = long random string
// KV binding required: USERS
//
// Optional variables:
// GH_OWNER=ColinNr1
// GH_REPO=Colinskis-Cards
// ALLOWED_ORIGIN=https://colinnr1.github.io

const DEFAULT_OWNER = 'ColinNr1';
const DEFAULT_REPO = 'Colinskis-Cards';

const INITIAL_USERS = {
  colinski: {username:'Colinski', displayName:'Colinski', role:'admin', passwordHash:'aea0fdff66e0e58dc8796c00aa4fbad856a22e67c3781bc75a199206fbee1790'},
  filinjo: {username:'Filinjo', displayName:'Filinjo', role:'user', passwordHash:'f5c4df2c62137c06fded1eef7091a3eb1d602c3e44a7d78038c0ab2cf7b6aac6'}
};

function json(data,status=200,origin='*'){
  return new Response(JSON.stringify(data),{status,headers:{
    'Content-Type':'application/json',
    'Access-Control-Allow-Origin':origin,
    'Access-Control-Allow-Headers':'Content-Type, Authorization',
    'Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  }});
}
function base64url(bytes){
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function sha256(text){
  const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function signToken(payload,secret){
  const head=base64url(new TextEncoder().encode(JSON.stringify({alg:'HS256',typ:'JWT'})));
  const body=base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(head+'.'+body));
  return head+'.'+body+'.'+base64url(new Uint8Array(sig));
}
async function verifyToken(token,secret){
  try{
    const [h,b,s]=token.split('.');
    const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
    const sig=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    const ok=await crypto.subtle.verify('HMAC',key,sig,new TextEncoder().encode(h+'.'+b));
    if(!ok)return null;
    const p=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0))));
    if(p.exp && Date.now()/1000>p.exp)return null;
    return p;
  }catch{return null}
}
async function getUser(env,username){
  const key='user:'+String(username).toLowerCase();
  let u=await env.USERS.get(key,'json');
  if(!u && INITIAL_USERS[String(username).toLowerCase()]){
    u=INITIAL_USERS[String(username).toLowerCase()];
    await env.USERS.put(key,JSON.stringify(u));
  }
  return u;
}
async function authUser(req,env){
  const raw=req.headers.get('Authorization')||'';
  if(!raw.startsWith('Bearer '))return null;
  return verifyToken(raw.slice(7),env.SESSION_SECRET);
}
function ghCfg(env){return {owner:env.GH_OWNER||DEFAULT_OWNER,repo:env.GH_REPO||DEFAULT_REPO}}
async function ghGet(env,path){
  const c=ghCfg(env);
  const r=await fetch(`https://api.github.com/repos/${c.owner}/${c.repo}/contents/${path}`,{headers:{Authorization:`Bearer ${env.GH_TOKEN}`,'User-Agent':'Colinskis-Card-Vault','Accept':'application/vnd.github+json'}});
  if(r.status===404)return {data:null,sha:null};
  if(!r.ok)throw new Error('GitHub read failed '+r.status);
  const j=await r.json();
  const txt=new TextDecoder().decode(Uint8Array.from(atob(j.content.replace(/\n/g,'')),c=>c.charCodeAt(0)));
  return {data:JSON.parse(txt),sha:j.sha};
}
async function ghPut(env,path,data,message){
  const c=ghCfg(env); const existing=await ghGet(env,path);
  const content=btoa(unescape(encodeURIComponent(JSON.stringify(data,null,2))));
  const body={message,content}; if(existing.sha)body.sha=existing.sha;
  const r=await fetch(`https://api.github.com/repos/${c.owner}/${c.repo}/contents/${path}`,{method:'PUT',headers:{Authorization:`Bearer ${env.GH_TOKEN}`,'User-Agent':'Colinskis-Card-Vault','Accept':'application/vnd.github+json','Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok)throw new Error('GitHub write failed '+r.status);
  return true;
}
async function allUsers(env){
  const keys=await env.USERS.list({prefix:'user:'});
  const out=[];
  for(const k of keys.keys){const u=await env.USERS.get(k.name,'json');if(u)out.push({username:u.username,displayName:u.displayName,role:u.role})}
  return out;
}

export default {
  async fetch(req,env){
    const origin=env.ALLOWED_ORIGIN||'*';
    if(req.method==='OPTIONS')return json({ok:true},200,origin);
    const url=new URL(req.url);
    try{
      if(url.pathname==='/api/login' && req.method==='POST'){
        const {username,password}=await req.json();
        const u=await getUser(env,username);
        if(!u || (await sha256(password||''))!==u.passwordHash)return json({error:'Invalid username or password'},401,origin);
        const token=await signToken({username:u.username,role:u.role,exp:Math.floor(Date.now()/1000)+60*60*24*30},env.SESSION_SECRET);
        return json({token,user:{username:u.username,displayName:u.displayName,role:u.role}},200,origin);
      }
      const me=await authUser(req,env);
      if(!me)return json({error:'Unauthorized'},401,origin);

      if(url.pathname==='/api/me' && req.method==='GET'){
        const u=await getUser(env,me.username); return json({user:{username:u.username,displayName:u.displayName,role:u.role}},200,origin);
      }
      if(url.pathname==='/api/admin/users' && req.method==='GET'){
        if(me.role!=='admin')return json({error:'Admin only'},403,origin);
        return json({users:await allUsers(env)},200,origin);
      }
      if(url.pathname==='/api/admin/users' && req.method==='POST'){
        if(me.role!=='admin')return json({error:'Admin only'},403,origin);
        const {username,password,displayName}=await req.json();
        if(!/^[A-Za-z0-9_-]{3,24}$/.test(username||''))return json({error:'Username must be 3-24 characters'},400,origin);
        if((password||'').length<6)return json({error:'Password must be at least 6 characters'},400,origin);
        const key='user:'+username.toLowerCase();
        if(await env.USERS.get(key))return json({error:'Username already exists'},409,origin);
        const u={username,displayName:displayName||username,role:'user',passwordHash:await sha256(password)};
        await env.USERS.put(key,JSON.stringify(u));
        await ghPut(env,`data/users/${username.toLowerCase()}.json`,{schemaVersion:8,cards:[],watchlist:[],binders:[],binderLayouts:{},showcaseSlots:[]},`Create Vault user ${username}`);
        return json({ok:true},201,origin);
      }
      if(url.pathname==='/api/vault' && req.method==='GET'){
        const r=await ghGet(env,`data/users/${me.username.toLowerCase()}.json`);
        return json({payload:r.data||{schemaVersion:8,cards:[]}},200,origin);
      }
      if(url.pathname==='/api/vault' && req.method==='PUT'){
        const {payload}=await req.json();
        await ghPut(env,`data/users/${me.username.toLowerCase()}.json`,payload,`Update ${me.username} vault`);
        return json({ok:true},200,origin);
      }
      if(url.pathname==='/api/trades' && req.method==='GET'){
        const r=await ghGet(env,'data/trades.json');
        return json(r.data||{listings:[],offers:[]},200,origin);
      }
      if(url.pathname==='/api/trades/listings' && req.method==='POST'){
        const {listing}=await req.json();
        if(listing.owner!==me.username)return json({error:'Owner mismatch'},403,origin);
        const r=await ghGet(env,'data/trades.json'); const d=r.data||{listings:[],offers:[]};
        d.listings=(d.listings||[]).filter(x=>x.listingId!==listing.listingId); d.listings.push(listing);
        await ghPut(env,'data/trades.json',d,`Trade listing by ${me.username}`);
        return json({ok:true},201,origin);
      }
      if(url.pathname.startsWith('/api/trades/listings/') && req.method==='DELETE'){
        const id=decodeURIComponent(url.pathname.split('/').pop());
        const r=await ghGet(env,'data/trades.json'); const d=r.data||{listings:[],offers:[]};
        const l=(d.listings||[]).find(x=>x.listingId===id);
        if(!l || l.owner!==me.username)return json({error:'Not allowed'},403,origin);
        d.listings=d.listings.filter(x=>x.listingId!==id);
        await ghPut(env,'data/trades.json',d,`Remove trade listing by ${me.username}`);
        return json({ok:true},200,origin);
      }
      if(url.pathname==='/api/trades/offers' && req.method==='POST'){
        const {offer}=await req.json();
        if(offer.fromUser!==me.username)return json({error:'Sender mismatch'},403,origin);
        const r=await ghGet(env,'data/trades.json'); const d=r.data||{listings:[],offers:[]};
        d.offers=(d.offers||[]).filter(x=>x.offerId!==offer.offerId); d.offers.push(offer);
        await ghPut(env,'data/trades.json',d,`Trade offer by ${me.username}`);
        return json({ok:true},201,origin);
      }
      if(url.pathname.startsWith('/api/trades/offers/') && req.method==='PATCH'){
        const id=decodeURIComponent(url.pathname.split('/').pop()); const {status}=await req.json();
        const r=await ghGet(env,'data/trades.json'); const d=r.data||{listings:[],offers:[]};
        const o=(d.offers||[]).find(x=>x.offerId===id);
        if(!o || o.toUser!==me.username)return json({error:'Not allowed'},403,origin);
        o.status=status;o.updatedAt=new Date().toISOString();
        await ghPut(env,'data/trades.json',d,`Trade offer ${status} by ${me.username}`);
        return json({ok:true},200,origin);
      }
      return json({error:'Not found'},404,origin);
    }catch(e){return json({error:e.message||'Server error'},500,origin)}
  }
};
