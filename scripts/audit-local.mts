// Offline, owner-side audit maintenance. Never available through MCP.
import {open,lstat,realpath,rename,unlink} from 'node:fs/promises';
import {resolve,dirname,join,relative,isAbsolute} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {createInterface} from 'node:readline/promises';
import {openAuditJournal,readAuditAnchor} from '../src/g1-audit-journal.ts';
const [action,profilePath,arg]=process.argv.slice(2);
if(!['inspect','anchor','archive','prune'].includes(action)||!profilePath||!isAbsolute(profilePath)||resolve(profilePath)!==profilePath)throw Error('Usage: node scripts/audit-local.mts inspect|anchor|archive|prune <absolute-profile.json> [archive-directory or archive-file]');
const sha=b=>createHash('sha256').update(b).digest('hex');
const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
async function directory(p){const s=await lstat(p);if(!isAbsolute(p)||resolve(p)!==p||!s.isDirectory()||s.isSymbolicLink()||resolve(await realpath(p))!==p)throw Error('Unsafe audit maintenance directory');return s;}
async function read(p,max){
  const s=await lstat(p);if(!isAbsolute(p)||resolve(p)!==p||!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>max||resolve(await realpath(p))!==p)throw Error('Unsafe audit maintenance file');
  const f=await open(p,'r');try{const before=await f.stat();if(!same(s,before)||before.size!==s.size||before.nlink!==1)throw Error('File replaced');
    const buf=Buffer.alloc(before.size);let at=0;while(at<buf.length){const r=await f.read(buf,at,buf.length-at,at);if(!r.bytesRead)throw Error('Truncated file');at+=r.bytesRead;}
    const after=await f.stat(),check=await lstat(p);if(!same(before,after)||!same(before,check)||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.nlink!==1||check.nlink!==1)throw Error('File changed');
    return buf;
  }finally{await f.close();}
}
function nested(a,b){const r=relative(a,b);return r===''||(!isAbsolute(r)&&r!=='..'&&!r.startsWith('..\\'));}
async function exclusive(p,bytes){
  const f=await open(p,'wx',0o600);try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}
  if(!(await read(p,32*1024*1024)).equals(bytes))throw Error('Written file verification failed');
}
async function confirm(phrase){if(!process.stdin.isTTY)throw Error('Interactive local owner confirmation required');const c=createInterface({input:process.stdin,output:process.stdout});let r;try{r=await c.question('Type '+phrase+' : ');}finally{c.close();}if(r!==phrase)throw Error('Owner confirmation refused');}
const raw=await read(profilePath,65536),p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
if(p.v!==1||!/^[-0-9a-f]{36}$/i.test(p.sessionId)||dirname(profilePath)!==p.controlRoot)throw Error('Invalid local profile');
const roots=[p.controlRoot,p.auditRoot,p.workspaceRoot,p.checkpointRoot,p.pendingRoot];
for(const r of roots)await directory(r);
const control=await directory(p.controlRoot),anchorPath=join(p.controlRoot,'audit-anchor.json');
const anchor=await readAuditAnchor(anchorPath,p.sessionId);
const logPath=join(p.auditRoot,'audit-v1.jsonl');await lstat(logPath);
const journal=await openAuditJournal(p.auditRoot,p.sessionId,{anchor,retentionDays:p.auditRetentionDays??30,maintenance:true});
try{
  const snapshot=await journal.snapshot(),summary=snapshot.summary;
  console.log(JSON.stringify(summary,null,2));
  if(action==='inspect'){console.log('AUDIT_VERIFIED');}
  else if(action==='anchor'){
    await confirm('ANCHOR '+summary.head);
    if(!same(control,await directory(p.controlRoot)))throw Error('Control root changed');
    const prior=await readAuditAnchor(anchorPath,p.sessionId);if(JSON.stringify(prior)!==JSON.stringify(anchor))throw Error('Prior anchor changed');
    const temp=join(p.controlRoot,'.audit-anchor-'+randomUUID()+'.tmp'),bytes=Buffer.from(JSON.stringify(snapshot.anchor)+'\n');
    await exclusive(temp,bytes);
    try{if(!same(control,await directory(p.controlRoot)))throw Error('Control root changed');await rename(temp,anchorPath);}finally{await unlink(temp).catch(e=>{if(e.code!=='ENOENT')throw e;});}
    const actual=await readAuditAnchor(anchorPath,p.sessionId);if(JSON.stringify(actual)!==JSON.stringify(snapshot.anchor))throw Error('Anchor verification failed');
    console.log('TRUSTED_ANCHOR_WRITTEN');
  }else if(action==='archive'){
    if(!arg||roots.some(r=>nested(r,arg)||nested(arg,r)))throw Error('Separate owner archive directory required');
    const identity=await directory(arg),target=join(arg,'audit-'+summary.workspaceId+'-'+summary.head+'.jsonl');
    await exclusive(target,snapshot.bytes);if(!same(identity,await directory(arg)))throw Error('Archive directory changed');
    console.log('ARCHIVE_VERIFIED SHA256='+summary.sha256);console.log(target);
  }else{
    if(!arg||roots.some(r=>nested(r,arg)))throw Error('Separate owner archive file required');
    if(!summary.retentionEligible||!anchor||anchor.seq!==summary.count||anchor.digest!==summary.head)throw Error('Retention threshold and current trusted anchor required');
    const archive=await read(arg,32*1024*1024);if(sha(archive)!==summary.sha256||!archive.equals(snapshot.bytes))throw Error('Archive mismatch');
    await confirm('PRUNE '+summary.head);
    if(!(await read(arg,32*1024*1024)).equals(archive))throw Error('Archive changed');
    await journal.retireArchived(archive,summary.head);
    console.log('CLOSED_JOURNAL_RETIRED; archive and anchor retained; new session ID required');
  }
}finally{await journal.close();}
