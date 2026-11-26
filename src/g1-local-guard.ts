// NB-0103: local, exact, single-use approvals; never an MCP approval endpoint.
// Production requires an owner-only control directory, separate from the executor's identity.
import {createHash,randomUUID} from 'node:crypto';
import {lstat,realpath,open} from 'node:fs/promises';
import {resolve,join,relative,isAbsolute} from 'node:path';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const sha=/^[a-f0-9]{64}$/;
const actions=new Set(['start_process','move_file','trash_file','restore_file']);
type Details=Record<string,unknown>;
type Pending={v:1;sessionId:string;id:string;action:string;details:Details;digest:string;expiresAt:number};
type Decision={status:'approved'|'awaiting_approval';approvalId:string;digest:string;expiresAt:number};
function canonical(v:unknown,depth=0):unknown{
  if(depth>5)throw Error('Approval details too deeply nested');
  if(v===null||typeof v==='boolean')return v;
  if(typeof v==='number'&&Number.isSafeInteger(v))return v;
  if(typeof v==='string'&&v.length<=4096&&!v.includes('\0'))return v;
  if(Array.isArray(v)&&v.length<=32)return v.map(x=>canonical(x,depth+1));
  if(v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype){
    const keys=Object.keys(v).sort();if(keys.length>32||keys.some(k=>!/^[_a-zA-Z0-9]{1,64}$/.test(k)))throw Error('Invalid approval keys');
    return Object.fromEntries(keys.map(k=>[k,canonical((v as Details)[k],depth+1)]));
  }
  throw Error('Unsupported approval details');
}
export function approvalDigest(sessionId:string,action:string,details:Details){
  const payload=JSON.stringify({v:1,sessionId,action,details:canonical(details)});
  if(Buffer.byteLength(payload)>16384)throw Error('Approval details too large');
  return createHash('sha256').update(payload).digest('hex');
}
async function inspectDir(path:string){
  const p=resolve(path),st=await lstat(p);
  if(!st.isDirectory()||st.isSymbolicLink()||resolve(await realpath(p))!==p)throw Error('Unsafe guard directory');
  return {p,dev:st.dev,ino:st.ino};
}
type Dir=Awaited<ReturnType<typeof inspectDir>>;
async function guardDir(d:Dir){const s=await inspectDir(d.p);if(s.dev!==d.dev||s.ino!==d.ino)throw Error('Guard directory changed');}
function nested(a:string,b:string){const r=relative(a,b);return r===''||(!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+(process.platform==='win32'?'\\':'/')));}
async function readApproval(path:string){
  const st=await lstat(path);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>2048||resolve(await realpath(path))!==path)throw Error('Unsafe local approval');
  const f=await open(path,'r');
  try{
    const before=await f.stat();if(before.dev!==st.dev||before.ino!==st.ino||before.nlink!==1||before.size!==st.size)throw Error('Approval replaced');
    const b=Buffer.alloc(2049),r=await f.read(b,0,b.length,0),after=await f.stat(),again=await lstat(path);
    if(r.bytesRead!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||again.ino!==before.ino||again.dev!==before.dev||again.nlink!==1)throw Error('Approval changed');
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,r.bytesRead))) as Record<string,unknown>;
  }finally{await f.close();}
}
export async function createLocalGuard(options:{sessionId:string;controlRoot:string;pendingRoot:string;ttlMs?:number;onStop?:(reason:"emergency_stop"|"guard_error")=>Promise<void>}){
  if(!uuid.test(options.sessionId))throw Error('Invalid guard session');
  const sessionId=options.sessionId.toLowerCase(),ttl=options.ttlMs??120_000;
  if(!Number.isSafeInteger(ttl)||ttl<100||ttl>120_000)throw Error('Invalid approval lifetime');
  const control=await inspectDir(options.controlRoot),pendingRoot=await inspectDir(options.pendingRoot);
  if(nested(control.p,pendingRoot.p)||nested(pendingRoot.p,control.p))throw Error('Guard roots must be separate');
  const pending=new Map<string,Pending>();let stopped=false,requests=0;
  let queue:Promise<unknown>=Promise.resolve();
  function serial<T>(fn:()=>Promise<T>){const q=queue.then(fn);queue=q.catch(()=>{});return q;}
  async function assertActive(){
    if(stopped)throw Error('Local guard stopped');
    try{
      await guardDir(control);await guardDir(pendingRoot);
      try{await lstat(join(control.p,'stop.flag'));throw Error('Local emergency stop');}
      catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
      if(stopped)throw Error('Local guard stopped');
    }catch(e){const first=!stopped;stopped=true;pending.clear();if(first)await options.onStop?.(e instanceof Error&&e.message==='Local emergency stop'?'emergency_stop':'guard_error').catch(()=>{});throw e;}
  }
  function stop(){stopped=true;pending.clear();}
  async function check(action:string,details:Details,approvalId?:string):Promise<Decision>{
    if(!actions.has(action))throw Error('Unrecognized approval action');
    const exact=canonical(details) as Details,hash=approvalDigest(sessionId,action,exact);
    return serial(async()=>{
      await assertActive();
      const now=Date.now();for(const [id,p] of pending)if(p.expiresAt<=now)pending.delete(id);
      if(approvalId!==undefined){
        if(!uuid.test(approvalId))throw Error('Invalid approval ID');
        const p=pending.get(approvalId);
        if(!p||p.action!==action||p.digest!==hash)throw Error('Approval missing, expired, consumed or mismatched');
        let a:Record<string,unknown>;
        try{a=await readApproval(join(control.p,p.id+'.json'));}
        catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return {status:'awaiting_approval',approvalId:p.id,digest:hash,expiresAt:p.expiresAt};throw e;}
        await assertActive();
        if(Object.keys(a).sort().join(',')!=='digest,expiresAt,id,sessionId,v'||a.v!==1||a.id!==p.id||a.sessionId!==sessionId||
          typeof a.digest!=='string'||!sha.test(a.digest)||a.digest!==hash||typeof a.expiresAt!=='number'||!Number.isSafeInteger(a.expiresAt)||
          a.expiresAt<=Date.now()||a.expiresAt>p.expiresAt||p.expiresAt<=Date.now())throw Error('Local approval not valid');
        // Consume before performing any side effect. Never re-use on ambiguous outcomes.
        pending.delete(p.id);
        return {status:'approved',approvalId:p.id,digest:hash,expiresAt:p.expiresAt};
      }
      const existing=[...pending.values()].find(p=>p.action===action&&p.digest===hash);
      if(existing)return {status:'awaiting_approval',approvalId:existing.id,digest:hash,expiresAt:existing.expiresAt};
      if(pending.size>=16||requests>=128)throw Error('Approval request budget exhausted');
      const p:Pending={v:1,sessionId,id:randomUUID(),action,details:exact,digest:hash,expiresAt:now+ttl};
      await guardDir(pendingRoot);
      const f=await open(join(pendingRoot.p,p.id+'.json'),'wx',0o600);
      try{await f.writeFile(JSON.stringify(p,null,2)+'\n','utf8');await f.sync();}finally{await f.close();}
      await assertActive();pending.set(p.id,p);requests++;
      return {status:'awaiting_approval',approvalId:p.id,digest:hash,expiresAt:p.expiresAt};
    });
  }
  return {check,assertActive,stop};
}
export type LocalGuard=Awaited<ReturnType<typeof createLocalGuard>>;
