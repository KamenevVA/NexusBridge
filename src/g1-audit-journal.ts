// NB-0103: bounded persistent, redacted, tamper-evident audit journal.
// Requires an owner-controlled OS ACL boundary; a hash chain is not a signature.
import { createHash } from 'node:crypto';
import { lstat, open, realpath, mkdir, rmdir, type FileHandle } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const sha=(s:string|Buffer)=>createHash('sha256').update(s).digest('hex');
const hashRE=/^[a-f0-9]{64}$/;
const uuidRE=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const actions=new Set([
  'ping','get_device_info','get_policy','get_audit_log','list_directory','directory_tree',
  'read_file','read_binary_file','read_multiple_files','get_file_info','search_files','search_content',
  'create_directory_attempt','create_directory_ok','write_file_attempt','write_file_ok',
  'edit_file_attempt','edit_file_ok','copy_file_attempt','copy_file_ok','checkpoint_created',
  'move_file_attempt','move_file_ok','trash_file_attempt','trash_file_ok',
  'restore_file_attempt','restore_file_ok','apply_patch_attempt','apply_patch_ok',
  'start_process_attempt','start_process_ok','read_process_output','list_sessions',
  'send_process_input_attempt','send_process_input_ok','terminate_process_attempt',
  'terminate_process_ok','process_exited','policy_revoked','kill_switch','permission_denied','approval_requested','approval_consumed'
]);
const allowedInput=new Set(['utc','action','path','template','id','checkpointId','sha256','expectedHash','scanned','outcome']);
const allowedFields=new Set(['pathDigest','templateDigest','id','checkpointId','sha256','expectedHash','scanned','outcome']);
const outcomes=new Set(['attempt','ok','denied','failed','cancelled','timed_out','unknown_outcome']);
type Fields={pathDigest?:string;templateDigest?:string;id?:string;checkpointId?:string;sha256?:string;expectedHash?:string|null;scanned?:number;outcome?:string};
type Body={v:1;seq:number;utc:string;actor:'local-guard';workspaceId:string;action:string;fields:Fields;prev:string};
export type AuditRecord=Body&{digest:string};
type Identity={dev:number;ino:number};
const same=(a:Identity,b:Identity)=>a.dev===b.dev&&a.ino===b.ino;
const genesis='0'.repeat(64);
function plain(x:unknown):x is Record<string,unknown>{return !!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function redacted(input:unknown):{action:string;fields:Fields}{
  if(!plain(input)||Object.keys(input).some(k=>!allowedInput.has(k))||typeof input.action!=='string'||!actions.has(input.action))throw Error('Unsupported audit event');
  const fields:Fields={};
  if(input.path!==undefined){if(typeof input.path!=='string'||input.path.length>1024)throw Error('Invalid audit path');fields.pathDigest=sha(input.path);}
  if(input.template!==undefined){if(typeof input.template!=='string'||input.template.length>64)throw Error('Invalid audit template');fields.templateDigest=sha(input.template);}
  for(const key of ['id','checkpointId'] as const){const v=input[key];if(v!==undefined){if(typeof v!=='string'||!uuidRE.test(v))throw Error('Invalid audit identifier');fields[key]=v.toLowerCase();}}
  for(const key of ['sha256','expectedHash'] as const){const v=input[key];if(v!==undefined){if(key==='expectedHash'&&v===null){fields.expectedHash=null;continue;}if(typeof v!=='string'||!hashRE.test(v))throw Error('Invalid audit hash');fields[key]=v;}}
  if(input.scanned!==undefined){if(typeof input.scanned!=='number'||!Number.isSafeInteger(input.scanned)||input.scanned<0||input.scanned>1_000_000)throw Error('Invalid audit count');fields.scanned=input.scanned;}
  if(input.outcome!==undefined){if(typeof input.outcome!=='string'||!outcomes.has(input.outcome))throw Error('Invalid audit outcome');fields.outcome=input.outcome;}
  return {action:input.action,fields};
}
function validFields(x:unknown):x is Fields{
  if(!plain(x)||Object.keys(x).some(k=>!allowedFields.has(k)))return false;
  for(const k of ['pathDigest','templateDigest','sha256'])if(x[k]!==undefined&&(typeof x[k]!=='string'||!hashRE.test(x[k] as string)))return false;
  if(x.expectedHash!==undefined&&x.expectedHash!==null&&(typeof x.expectedHash!=='string'||!hashRE.test(x.expectedHash)))return false;
  for(const k of ['id','checkpointId'])if(x[k]!==undefined&&(typeof x[k]!=='string'||!uuidRE.test(x[k] as string)))return false;
  if(x.scanned!==undefined&&(typeof x.scanned!=='number'||!Number.isSafeInteger(x.scanned)||x.scanned<0||x.scanned>1_000_000))return false;
  return x.outcome===undefined||(typeof x.outcome==='string'&&outcomes.has(x.outcome));
}
function bodyOf(r:AuditRecord):Body{return {v:r.v,seq:r.seq,utc:r.utc,actor:r.actor,workspaceId:r.workspaceId,action:r.action,fields:r.fields,prev:r.prev};}
function decode(buffer:Buffer,workspaceId:string,maxRecords:number):AuditRecord[]{
  const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer);
  if(!text)return [];
  if(!text.endsWith('\n'))throw Error('Incomplete audit record');
  const lines=text.slice(0,-1).split('\n');if(lines.length>maxRecords)throw Error('Audit capacity exceeded');
  const records:AuditRecord[]=[];let prev=genesis;
  for(const line of lines){
    if(line.length>4096)throw Error('Oversized audit record');
    const r=JSON.parse(line) as AuditRecord;
    if(!plain(r)||Object.keys(r).length!==9||r.v!==1||r.seq!==records.length+1||r.actor!=='local-guard'||r.workspaceId!==workspaceId||
       typeof r.utc!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.utc)||!Number.isFinite(Date.parse(r.utc))||
       !actions.has(r.action)||!validFields(r.fields)||r.prev!==prev||typeof r.digest!=='string'||!hashRE.test(r.digest)||
       sha(JSON.stringify(bodyOf(r)))!==r.digest)throw Error('Audit chain validation failed');
    records.push(r);prev=r.digest;
  }
  return records;
}
export async function openAuditJournal(rootPath:string,workspaceId:string,options:{maxBytes?:number;maxRecords?:number}={}){
  if(!uuidRE.test(workspaceId))throw Error('Invalid workspace ID');
  workspaceId=workspaceId.toLowerCase();
  const maxBytes=options.maxBytes??8*1024*1024,maxRecords=options.maxRecords??20_000;
  if(!Number.isSafeInteger(maxBytes)||maxBytes<512||maxBytes>32*1024*1024||!Number.isSafeInteger(maxRecords)||maxRecords<1||maxRecords>50_000)throw Error('Invalid journal limits');
  const root=resolve(rootPath),p=join(root,'audit-v1.jsonl');
  const initial=await lstat(root);
  if(!initial.isDirectory()||initial.isSymbolicLink()||resolve(await realpath(root))!==root)throw Error('Unsafe audit root');
  // Atomic single-writer lease; after a crash, local owner recovery is required.
  const lock=join(root,'audit-v1.lock');
  await mkdir(lock);
  const lease=await lstat(lock);
  async function checkLease(){
    const r=await lstat(root),l=await lstat(lock);
    if(!r.isDirectory()||r.isSymbolicLink()||!same(r,initial)||!l.isDirectory()||l.isSymbolicLink()||!same(l,lease)||resolve(await realpath(lock))!==lock)throw Error('Audit lease changed');
  }
  async function release(){await checkLease();await rmdir(lock);}
  try{
  const existing=await lstat(p).catch(e=>{if((e as NodeJS.ErrnoException).code==='ENOENT')return undefined;throw e;});
  if(existing&&(!existing.isFile()||existing.isSymbolicLink()||existing.nlink!==1||existing.size>maxBytes||resolve(await realpath(p))!==p))throw Error('Unsafe audit file');
  const fd:FileHandle=await open(p,existing?'r+':'wx+',0o600);
  try{
    const original=await fd.stat();
    if(!original.isFile()||original.nlink!==1||(existing&&!same(original,existing))||original.size>maxBytes)throw Error('Audit identity changed');
    async function guard(size:number){
      await checkLease();
      const r=await lstat(root),s=await lstat(p),f=await fd.stat();
      if(!r.isDirectory()||r.isSymbolicLink()||!same(r,initial)||resolve(await realpath(root))!==root||
         !s.isFile()||s.isSymbolicLink()||s.nlink!==1||f.nlink!==1||!same(s,original)||!same(f,original)||
         resolve(await realpath(p))!==p||s.size!==size||f.size!==size)throw Error('Audit boundary changed');
    }
    await guard(original.size);
    const data=Buffer.alloc(original.size);
    let at=0;while(at<data.length){const r=await fd.read(data,at,data.length-at,at);if(!r.bytesRead)throw Error('Audit read truncated');at+=r.bytesRead;}
    await guard(original.size);
    let records=decode(data,workspaceId,maxRecords),size=original.size,head=records.at(-1)?.digest??genesis;
    let tail:Promise<unknown>=Promise.resolve(),closed=false,poisoned=false;
    function serial<T>(fn:()=>Promise<T>){const q=tail.then(fn);tail=q.catch(()=>{});return q;}
    function usable(){if(closed||poisoned)throw Error('Audit journal unavailable');}
    async function verifyCurrent(){
      await guard(size);
      // Bound the read and verify the full chain on reopen and explicit verification.
      const bytes=Buffer.alloc(size);let offset=0;while(offset<size){const r=await fd.read(bytes,offset,size-offset,offset);if(!r.bytesRead)throw Error('Audit read truncated');offset+=r.bytesRead;}
      const actual=decode(bytes,workspaceId,maxRecords);
      if(actual.length!==records.length||(actual.at(-1)?.digest??genesis)!==head)throw Error('Audit chain changed');
      await guard(size);
    }
    function append(input:unknown){
      const {action,fields}=redacted(input);
      return serial(async()=>{
        usable();
        try{
          await verifyCurrent();
          const body:Body={v:1,seq:records.length+1,utc:new Date().toISOString(),actor:'local-guard',workspaceId,action,fields,prev:head};
          const record:AuditRecord={...body,digest:sha(JSON.stringify(body))};
          const bytes=Buffer.from(JSON.stringify(record)+'\n','utf8');
          if(size+bytes.length>maxBytes||records.length>=maxRecords)throw Error('Audit capacity exceeded');
          let offset=0;while(offset<bytes.length){const r=await fd.write(bytes,offset,bytes.length-offset,size+offset);if(!r.bytesWritten)throw Error('Audit write incomplete');offset+=r.bytesWritten;}
          await fd.sync();await guard(size+bytes.length);
          size+=bytes.length;head=record.digest;records.push(record);
          return structuredClone(record);
        }catch(e){poisoned=true;throw e;}
      });
    }
    function page(offset=0,limit=100){return serial(async()=>{
      usable();if(!Number.isSafeInteger(offset)||offset<0||offset>records.length||!Number.isSafeInteger(limit)||limit<1||limit>200)throw Error('Invalid audit pagination');
      try{await verifyCurrent();}catch(e){poisoned=true;throw e;}
      return {records:structuredClone(records.slice(offset,offset+limit)),nextOffset:offset+limit<records.length?offset+limit:null,head};
    });}
    function close(){return serial(async()=>{if(!closed){closed=true;await fd.close();await release();records=[];}});}
    return {append,page,close};
  }catch(e){await fd.close().catch(()=>{});throw e;}
  }catch(e){await release().catch(()=>{});throw e;}
}
