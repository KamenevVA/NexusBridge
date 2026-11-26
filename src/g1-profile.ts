// G1 local owner-selected profile. No remote endpoint or privilege escalation.
// Requires a separately prepared low-privilege Windows principal and owner-controlled ACLs.
import {z} from 'zod';
import {lstat,realpath,open,unlink} from 'node:fs/promises';
import {resolve,dirname,join,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {makeMvp} from './mvp-core.ts';
import {createLocalGuard} from './g1-local-guard.ts';
import {openAuditJournal,readAuditAnchor} from './g1-audit-journal.ts';
const path=z.string().min(4).max(1024);
const profileSchema=z.object({
  v:z.literal(1),sessionId:z.string().uuid(),executorSid:z.string().regex(/^S-1-5-[0-9-]+$/),expiresAt:z.number().int(),
  workspaceRoot:path,checkpointRoot:path,auditRoot:path,controlRoot:path,pendingRoot:path,
  scopes:z.object({read:z.literal(true),write:z.boolean(),exec:z.boolean()}).strict(),
  appContainerProfile:z.string().regex(/^NexusBridgeExec[0-9a-f]{32}$/).optional(),
  auditRetentionDays:z.number().int().min(1).max(365).default(30),
  commands:z.record(z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),z.object({exe:path,cwd:path,args:z.array(z.string().max(4096)).max(32),timeoutMs:z.number().int().min(100).max(60000),input:z.boolean()}).strict())
}).strict();
const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
function local(p:string){if(!/^[A-Za-z]:\\/.test(p)||p.slice(2).includes(':')||resolve(p)!==p||p===p.slice(0,3))throw Error('Canonical local non-root path required');return p;}
function nested(a:string,b:string){const r=relative(a,b);return r===''||(!isAbsolute(r)&&r!=='..'&&!r.startsWith('..\\'));}
async function directory(p:string){local(p);const st=await lstat(p);if(!st.isDirectory()||st.isSymbolicLink()||resolve(await realpath(p))!==p)throw Error('Unsafe profile directory');return {p,dev:st.dev,ino:st.ino};}
async function readProfile(p:string){
  local(p);const st=await lstat(p);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>65536||resolve(await realpath(p))!==p)throw Error('Unsafe profile file');
  const f=await open(p,'r');try{const before=await f.stat();if(before.dev!==st.dev||before.ino!==st.ino||before.size!==st.size||before.nlink!==1)throw Error('Profile changed');
    const buf=Buffer.alloc(before.size);let offset=0;while(offset<buf.length){const r=await f.read(buf,offset,buf.length-offset,offset);if(!r.bytesRead)throw Error('Profile truncated');offset+=r.bytesRead;}
    const after=await f.stat(),check=await lstat(p);if(after.ino!==before.ino||after.dev!==before.dev||after.size!==before.size||after.mtimeMs!==before.mtimeMs||check.ino!==before.ino||check.dev!==before.dev||check.nlink!==1)throw Error('Profile changed');
    return {value:profileSchema.parse(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buf))),hash:sha(buf),dev:before.dev,ino:before.ino};
  }finally{await f.close();}
}
async function requireReadOnlyFile(p:string){
  try{const h=await open(p,'r+');await h.close();}catch(e){if(['EACCES','EPERM'].includes((e as NodeJS.ErrnoException).code??''))return;throw e;}throw Error('Executor can write protected file');
}
async function requireReadOnlyDirectory(p:string){
  const marker=join(p,'.nb-acl-test-'+randomUUID());
  try{const h=await open(marker,'wx');await h.close();}catch(e){if(['EACCES','EPERM'].includes((e as NodeJS.ErrnoException).code??''))return;throw e;}
  await unlink(marker);throw Error('Executor can write protected directory');
}
if(process.platform!=='win32'||process.arch!=='x64'||process.argv.length!==3)throw Error('Usage: node src/g1-profile.ts <owner-protected-profile.json>');
const profilePath=local(process.argv[2]),initial=await readProfile(profilePath),p=initial.value;
const whoami=join(process.env.SystemRoot??'C:\\Windows','System32','whoami.exe');
const user=execFileSync(whoami,['/user','/fo','csv','/nh'],{encoding:'utf8',windowsHide:true}),groups=execFileSync(whoami,['/groups','/fo','csv','/nh'],{encoding:'utf8',windowsHide:true});
const sid=user.match(/S-1-5-[0-9-]+/)?.[0];
if(sid!==p.executorSid||['S-1-5-18','S-1-5-19','S-1-5-20'].includes(sid)||groups.includes('S-1-5-32-544'))throw Error('Dedicated non-admin executor required');
if(p.expiresAt<=Date.now()||p.expiresAt>Date.now()+3600000||Object.keys(p.commands).length>8||(!p.scopes.exec&&(Object.keys(p.commands).length||p.appContainerProfile))||(p.scopes.exec&&!p.appContainerProfile))throw Error('Invalid local profile policy');
const appRoot=resolve(fileURLToPath(new URL('../',import.meta.url)));
const dirs=await Promise.all([p.workspaceRoot,p.checkpointRoot,p.auditRoot,p.controlRoot,p.pendingRoot,appRoot].map(directory));
for(let i=0;i<dirs.length;i++)for(let j=i+1;j<dirs.length;j++)if(nested(dirs[i].p,dirs[j].p)||nested(dirs[j].p,dirs[i].p))throw Error('Profile roots overlap');
if(dirname(profilePath)!==p.controlRoot||dirs[0].dev!==dirs[1].dev)throw Error('Profile location or checkpoint volume invalid');
await requireReadOnlyFile(profilePath);await requireReadOnlyDirectory(p.controlRoot);await requireReadOnlyDirectory(appRoot);
for(const dir of ['src','scripts','node_modules','.runtime/native'])await requireReadOnlyDirectory(join(appRoot,dir));
for(const file of ['package.json','src/g1-profile.ts','src/g1-local-guard.ts','src/g1-audit-journal.ts','src/mvp-core.ts','src/processes.ts','src/workspace.ts'])await requireReadOnlyFile(join(appRoot,file));
for(const file of ['NexusBridge.Job.exe','NexusBridge.FileMove.exe','NexusBridge.AppContainer.exe'])await requireReadOnlyFile(join(appRoot,'.runtime','native',file));
for(const t of Object.values(p.commands)){
  local(t.exe);local(t.cwd);
  if(!nested(p.workspaceRoot,t.cwd)||[p.workspaceRoot,p.checkpointRoot,p.auditRoot,p.pendingRoot].some(r=>nested(r,t.exe)))throw Error('Command path outside local policy');
  await requireReadOnlyFile(t.exe);
}
const anchorPath=join(p.controlRoot,'audit-anchor.json'),anchor=await readAuditAnchor(anchorPath,p.sessionId);if(anchor)await requireReadOnlyFile(anchorPath);
const journal=await openAuditJournal(p.auditRoot,p.sessionId,{anchor,requireAnchorOnExisting:true,retentionDays:p.auditRetentionDays});
let enabled=true,revocationRecorded=false;
async function revoke(action:'kill_switch'|'policy_revoked'){
  enabled=false;if(!revocationRecorded){revocationRecorded=true;await journal.append({action,outcome:'ok'}).catch(()=>{});}
}
const guard=await createLocalGuard({sessionId:p.sessionId,controlRoot:p.controlRoot,pendingRoot:p.pendingRoot,onStop:async reason=>revoke(reason==='emergency_stop'?'kill_switch':'policy_revoked')});
async function assertActive(){
  if(!enabled)throw Error('Profile stopped');
  try{if(Date.now()>=p.expiresAt)throw Error('Profile expired');
    const check=await readProfile(profilePath);if(check.hash!==initial.hash||check.dev!==initial.dev||check.ino!==initial.ino)throw Error('Profile replaced');
    for(const d of dirs){const s=await directory(d.p);if(s.dev!==d.dev||s.ino!==d.ino)throw Error('Profile root changed');}
    await guard.assertActive();
  }catch(e){await revoke('policy_revoked');throw e;}
}
const m=await makeMvp({root:p.workspaceRoot,checkpointRoot:p.checkpointRoot,write:p.scopes.write,exec:p.scopes.exec,guard,assertActive,
  audit:async e=>{await assertActive();try{await journal.append(e);}catch(e){await revoke('policy_revoked');throw e;}},
  auditPage:async (offset,limit)=>{await assertActive();try{return await journal.page(offset,limit);}catch(e){await revoke('policy_revoked');throw e;}},
  commands:p.commands,appContainerProfile:p.appContainerProfile});
const transport=new StdioServerTransport();let closing=false;
async function stop(){if(closing)return;closing=true;enabled=false;await m.stop().catch(()=>{});await journal.close().catch(()=>{});}
await m.server.connect(transport);
process.stdin.once('end',()=>void stop());process.once('SIGINT',()=>void stop());process.once('SIGTERM',()=>void stop());
console.error('NexusBridge dedicated local profile ready');
