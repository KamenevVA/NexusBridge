// Local owner CLI. Never exposed as an MCP tool; no automatic production approvals.
import {lstat,realpath,open,readdir} from 'node:fs/promises';
import {resolve,join,dirname,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createInterface} from 'node:readline/promises';
import {approvalDigest} from '../src/g1-local-guard.ts';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const actions=new Set(['start_process','move_file','trash_file','restore_file']);
const [action,session,id]=process.argv.slice(2);
if(!session||!['list','approve','stop'].includes(action))throw Error('Usage: node scripts/guard-local.mts list|approve|stop alpha-SESSION|absolute-profile.json [approval UUID]');
async function readSmall(p,max){
  const s=await lstat(p);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>max||resolve(await realpath(p))!==p)throw Error('Unsafe local request file');
  const f=await open(p,'r');try{const before=await f.stat();if(before.dev!==s.dev||before.ino!==s.ino||before.size!==s.size||before.nlink!==1)throw Error('Request replaced');
    const buf=Buffer.alloc(before.size);let at=0;while(at<buf.length){const r=await f.read(buf,at,buf.length-at,at);if(!r.bytesRead)throw Error('Truncated local request');at+=r.bytesRead;}
    const after=await f.stat(),check=await lstat(p);if(after.ino!==before.ino||after.dev!==before.dev||after.size!==before.size||after.mtimeMs!==before.mtimeMs||check.ino!==before.ino||check.dev!==before.dev||check.nlink!==1)throw Error('Request changed');
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buf));
  }finally{await f.close();}
}
let control,pending,sessionId;
if(/^alpha-[A-Za-z0-9]+$/.test(session)){
  const base=resolve(fileURLToPath(new URL('../.runtime/',import.meta.url))),root=join(base,session);
  control=join(root,'control');pending=join(root,'pending');
}else{
  if(!/^[A-Za-z]:\\/.test(session)||resolve(session)!==session||!session.endsWith('.json'))throw Error('Canonical profile path required');
  const p=await readSmall(session,65536);
  if(p.v!==1||!uuid.test(p.sessionId)||typeof p.controlRoot!=='string'||typeof p.pendingRoot!=='string'||dirname(session)!==p.controlRoot)throw Error('Invalid local profile');
  control=p.controlRoot;pending=p.pendingRoot;sessionId=p.sessionId;
}
function nested(a,b){const r=relative(a,b);return r===''||(!isAbsolute(r)&&r!=='..'&&!r.startsWith('..\\'));}
if(nested(control,pending)||nested(pending,control))throw Error('Guard roots overlap');
for(const p of [control,pending]){const s=await lstat(p);if(!s.isDirectory()||s.isSymbolicLink()||resolve(await realpath(p))!==p)throw Error('Unsafe local guard directory');}
async function readPending(id){
  if(!uuid.test(id))throw Error('Invalid approval UUID');
  const p=await readSmall(join(pending,id+'.json'),20000);
  if(p.v!==1||p.id!==id||!uuid.test(p.sessionId)||(sessionId&&p.sessionId!==sessionId)||!/^[a-f0-9]{64}$/.test(p.digest)||!Number.isSafeInteger(p.expiresAt)||!actions.has(p.action)||approvalDigest(p.sessionId,p.action,p.details)!==p.digest)throw Error('Invalid or altered pending request');
  return p;
}
const show=p=>JSON.stringify(p,null,2).replace(/[\u202A-\u202E\u2066-\u2069]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
async function ensureNotStopped(){try{await lstat(join(control,'stop.flag'));throw Error('Session stopped');}catch(e){if(e.code!=='ENOENT')throw e;}}
if(action==='list'){
  for(const file of await readdir(pending)){if(!file.endsWith('.json')||!uuid.test(file.slice(0,-5)))continue;const p=await readPending(file.slice(0,-5));if(p.expiresAt>Date.now())console.log(show(p));}
}else if(action==='stop'){
  const f=await open(join(control,'stop.flag'),'wx',0o600);try{await f.writeFile('STOP\n');await f.sync();}finally{await f.close();}console.log('Emergency stop requested. A new approved session is required.');
}else{
  await ensureNotStopped();const p=await readPending(id);if(p.expiresAt<=Date.now())throw Error('Request expired');
  console.log('Review the exact local operation:\n'+show(p));
  if(!process.stdin.isTTY)throw Error('Interactive local owner confirmation required');
  const cli=createInterface({input:process.stdin,output:process.stdout});let answer;
  try{answer=await cli.question('Type APPROVE '+p.digest+' : ');}finally{cli.close();}
  if(answer!=='APPROVE '+p.digest||Date.now()>=p.expiresAt)throw Error('Approval refused or expired');
  await ensureNotStopped();const current=await readPending(id);if(JSON.stringify(current)!==JSON.stringify(p))throw Error('Pending request changed');
  const f=await open(join(control,id+'.json'),'wx',0o600);try{await f.writeFile(JSON.stringify({v:1,id,sessionId:p.sessionId,digest:p.digest,expiresAt:p.expiresAt}));await f.sync();}finally{await f.close();}
  console.log('One-time approval recorded. Repeat the same MCP operation with its approvalId.');
}
