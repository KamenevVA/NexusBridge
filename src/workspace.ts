// G1 workspace prototype. Requires an OS-isolated, owner-selected root; not an OS sandbox.
import { createHash, randomUUID } from 'node:crypto';
import { lstat, realpath, open, mkdir, readdir, rename, unlink } from 'node:fs/promises';
import { resolve, join, relative, isAbsolute, dirname } from 'node:path';
const digest=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
const maxBytes=4*1024*1024;
const blocked=/^(?:\.git|\.ssh|\.aws|\.env(?:\..*)?|\.nexusbridge|node_modules|\.nb-tmp-.*|credentials(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|pfx|p12|key))$/i;
const reserved=/^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i;
type Identity={dev:number;ino:number};
function same(a:Identity,b:Identity){return a.dev===b.dev&&a.ino===b.ino}
function parts(p:string){
  if(p===''||p==='.')return [];
  if(p.length>1024||isAbsolute(p)||p.startsWith('/')||p.includes('\\'))throw Error('Relative slash-separated path required');
  const a=p.split('/');
  if(a.length>32||a.some(x=>!x||x==='.'||x==='..'||x.length>180||/[<>:"|?*\x00-\x1f]/.test(x)||/[. ]$/.test(x)||reserved.test(x)||blocked.test(x)))throw Error('Path denied');
  return a;
}
const utf8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
export async function createWorkspace(rootPath:string, options:{write:boolean;checkpointRoot?:string;assertActive:()=>Promise<void>;audit:(e:object)=>Promise<void>}){
  const root=resolve(rootPath);
  const rootStat=await lstat(root);
  if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||resolve(await realpath(root))!==root)throw Error('Unsafe workspace root');
  const checkpointRoot=options.checkpointRoot?resolve(options.checkpointRoot):undefined;
  const checkpointStat=checkpointRoot?await lstat(checkpointRoot):undefined;
  const outside=(a:string,b:string)=>{const r=relative(a,b);return isAbsolute(r)||r==='..'||r.startsWith('..'+(process.platform==='win32'?'\\':'/'));};
  if(checkpointRoot&&(!checkpointStat?.isDirectory()||checkpointStat.isSymbolicLink()||resolve(await realpath(checkpointRoot))!==checkpointRoot||!outside(root,checkpointRoot)||!outside(checkpointRoot,root)))throw Error('Checkpoint root must be separate');
  async function guardCheckpoint(){if(!checkpointRoot||!checkpointStat)throw Error('Checkpoint store required for replacement');const s=await lstat(checkpointRoot);if(!s.isDirectory()||s.isSymbolicLink()||!same(s,checkpointStat)||resolve(await realpath(checkpointRoot))!==checkpointRoot)throw Error('Checkpoint store changed');return checkpointRoot;}
  async function active(write=false){await options.assertActive();if(write&&!options.write)throw Error('Write denied');const st=await lstat(root);if(!st.isDirectory()||st.isSymbolicLink()||!same(st,rootStat)||resolve(await realpath(root))!==root)throw Error('Workspace replaced');}
  async function inspect(p:string,missing=false){
    await active();const a=parts(p);let current=root;
    for(let i=0;i<a.length;i++){
      current=join(current,a[i]);
      const st=await lstat(current).catch(e=>{if(missing&&i===a.length-1&&(e as NodeJS.ErrnoException).code==='ENOENT')return undefined;throw e;});
      if(!st)return {path:current,st:undefined};
      if(st.isSymbolicLink()||resolve(await realpath(current))!==current||(i<a.length-1&&!st.isDirectory())||(!st.isFile()&&!st.isDirectory())||(st.isFile()&&st.nlink!==1))throw Error('Unsafe workspace object');
    }
    const st=await lstat(current);return {path:current,st};
  }
  async function readBytes(p:string){
    const x=await inspect(p);if(!x.st?.isFile()||x.st.size>maxBytes)throw Error('Not a bounded regular file');
    const f=await open(x.path,'r');try{const st=await f.stat();if(!st.isFile()||st.nlink!==1||!same(st,x.st)||st.size>maxBytes)throw Error('File identity changed');
      const buf=Buffer.alloc(maxBytes+1);let offset=0;while(offset<buf.length){const r=await f.read(buf,offset,buf.length-offset,offset);if(!r.bytesRead)break;offset+=r.bytesRead;}
      const after=await f.stat();if(offset>maxBytes||!same(st,after)||after.size!==st.size||after.mtimeMs!==st.mtimeMs)throw Error('File changed during read');
      const check=await inspect(p);if(!check.st||!same(check.st,after))throw Error('File replaced');return buf.subarray(0,offset);
    }finally{await f.close();}
  }
  async function event(action:string,path:string,detail:object={}){await options.audit({utc:new Date().toISOString(),action,path,...detail});}
  let queue=Promise.resolve();
  function serial<T>(fn:()=>Promise<T>){const next=queue.then(fn);queue=next.then(()=>{},()=>{});return next;}
  async function list(p='',limit=100,offset=0){
    if(!Number.isSafeInteger(limit)||limit<1||limit>200||!Number.isSafeInteger(offset)||offset<0)throw Error('Invalid pagination');
    const x=await inspect(p);if(!x.st?.isDirectory())throw Error('Not a directory');
    const entries=await readdir(x.path,{withFileTypes:true});
    const names=entries.map(e=>e.name).sort((a,b)=>a.localeCompare(b)).filter(n=>{try{parts(n);return true;}catch{return false;}});
    const result=[];for(const name of names.slice(offset,offset+limit)){try{const q=await inspect(p&&p!=='.'?p+'/'+name:name);result.push({name,type:q.st?.isDirectory()?'directory':'file',bytes:q.st?.isFile()?q.st.size:undefined});}catch{/* unsafe entries excluded */}}
    await event('list_directory',p);return {entries:result,nextOffset:offset+limit<names.length?offset+limit:null};
  }
  async function read(p:string,offset=0,length=12000){
    if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(length)||length<1||length>24000)throw Error('Invalid pagination');
    const bytes=await readBytes(p);const text=utf8.decode(bytes);const sha256=digest(bytes);
    await event('read_file',p,{sha256});
    return {text:text.slice(offset,offset+length),sha256,bytes:bytes.length,nextOffset:offset+length<text.length?offset+length:null};
  }
  async function info(p:string){const x=await inspect(p);if(!x.st)throw Error('Missing object');const sha256=x.st.isFile()?digest(await readBytes(p)):undefined;await event('get_file_info',p,{sha256});return {type:x.st.isDirectory()?'directory':'file',bytes:x.st.size,sha256};}
  async function createDirectory(p:string){return serial(async()=>{await active(true);if(!parts(p).length)throw Error('Root denied');const x=await inspect(p,true);if(x.st)throw Error('Already exists');await event('create_directory_attempt',p);await active(true);await mkdir(x.path);await inspect(p);await event('create_directory_ok',p);return {created:true};});}
  async function writeBytes(p:string,bytes:Buffer,expectedHash:string|null){return serial(async()=>{
    await active(true);if(!parts(p).length)throw Error('Root denied');
    if(bytes.length>maxBytes)throw Error('File too large');
    const x=await inspect(p,true);let prior:Buffer|undefined;
    if(x.st){if(!x.st.isFile()||expectedHash===null)throw Error('Conflict: explicit hash required');prior=await readBytes(p);if(digest(prior)!==expectedHash)throw Error('Conflict: hash mismatch');}
    else if(expectedHash!==null)throw Error('Conflict: file missing');
    const sha256=digest(bytes);await event('write_file_attempt',p,{expectedHash,sha256});
    if(prior){
      const store=await guardCheckpoint(),checkpointId=randomUUID(),backup=join(store,checkpointId+'.bak');
      const b=await open(backup,'wx',0o600);try{await b.writeFile(prior);await b.sync();}finally{await b.close();}
      await event('checkpoint_created',p,{checkpointId,sha256:expectedHash});
      const temp=join(dirname(x.path),'.nb-tmp-'+randomUUID());
      let made=false;
      try{const f=await open(temp,'wx',0o600);made=true;try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}
        await active(true);await guardCheckpoint();const check=await inspect(p);if(!check.st||!x.st||!same(check.st,x.st)||digest(await readBytes(p))!==expectedHash)throw Error('Conflict: file changed');
        // Atomic rename where supported. No external-writer CAS: isolated workspace required.
        await rename(temp,x.path);made=false;
        if(digest(await readBytes(p))!==sha256)throw Error('Unknown write outcome');
        await event('write_file_ok',p,{sha256,checkpointId});return {sha256,bytes:bytes.length,checkpointId};
      }finally{if(made)await unlink(temp).catch(()=>{});}
    }
    await active(true);const check=await inspect(p,true);if(check.st)throw Error('Conflict: file appeared');
    const f=await open(x.path,'wx',0o600);try{const st=await f.stat();if(!st.isFile()||st.nlink!==1)throw Error('Unsafe created file');await f.writeFile(bytes);await f.sync();}finally{await f.close();}
    const actual=await readBytes(p);if(digest(actual)!==sha256)throw Error('Unknown write outcome');
    await event('write_file_ok',p,{sha256});return {sha256,bytes:bytes.length};
  });}
  async function write(p:string,content:string,expectedHash:string|null){return writeBytes(p,Buffer.from(content,'utf8'),expectedHash);}
  async function edit(p:string,oldText:string,newText:string,expectedHash:string){if(!oldText)throw Error('Empty match');const bytes=await readBytes(p);if(digest(bytes)!==expectedHash)throw Error('Conflict: hash mismatch');const text=utf8.decode(bytes);const index=text.indexOf(oldText);if(index<0||text.indexOf(oldText,index+1)>=0)throw Error('Expected exactly one match');return write(p,text.slice(0,index)+newText+text.slice(index+oldText.length),expectedHash);}
  async function readBinary(p:string,offset=0,length=12000){
    if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(length)||length<1||length>24000)throw Error('Invalid byte pagination');
    const bytes=await readBytes(p),sha256=digest(bytes);
    if(offset>bytes.length)throw Error('Byte offset beyond file');
    await event('read_binary_file',p,{sha256});
    return {base64:bytes.subarray(offset,offset+length).toString('base64'),sha256,bytes:bytes.length,nextOffset:offset+length<bytes.length?offset+length:null};
  }
  async function writeBinary(p:string,base64:string,expectedHash:string|null){
    if(base64.length>Math.ceil(maxBytes/3)*4||base64.length%4!==0||!/^[A-Za-z0-9+/]*={0,2}$/.test(base64))throw Error('Invalid bounded base64');
    const bytes=Buffer.from(base64,'base64');
    if(bytes.toString('base64')!==base64||bytes.length>maxBytes)throw Error('Non-canonical or oversized base64');
    return writeBytes(p,bytes,expectedHash);
  }
  async function applyPatch(p:string,edits:ReadonlyArray<{oldText:string;newText:string}>,expectedHash:string){
    await active(true);
    if(!edits.length||edits.length>32)throw Error('Invalid patch size');
    const bytes=await readBytes(p);
    if(digest(bytes)!==expectedHash)throw Error('Conflict: hash mismatch');
    let text=utf8.decode(bytes);
    for(const edit of edits){
      if(!edit.oldText||edit.oldText.length>24000||edit.newText.length>24000)throw Error('Invalid patch edit');
      const i=text.indexOf(edit.oldText);
      if(i<0||text.indexOf(edit.oldText,i+1)>=0)throw Error('Expected exactly one match per edit');
      text=text.slice(0,i)+edit.newText+text.slice(i+edit.oldText.length);
      if(Buffer.byteLength(text,'utf8')>maxBytes)throw Error('Patch exceeds file limit');
    }
    await event('apply_patch_attempt',p,{expectedHash,sha256:digest(Buffer.from(text,'utf8'))});
    const result=await write(p,text,expectedHash);
    await event('apply_patch_ok',p,{sha256:result.sha256,checkpointId:result.checkpointId});
    return result;
  }
  async function copy(source:string,destination:string){return writeBytes(destination,await readBytes(source),null);}
  async function tree(p:string,depth=2){if(!Number.isSafeInteger(depth)||depth<0||depth>5)throw Error('Invalid tree depth');const result:Array<{path:string;type:string}>=[];const queue=[{path:p,depth:0}];let truncated=false;while(queue.length&&result.length<200){const q=queue.shift()!;const page=await list(q.path,200,0);if(page.nextOffset!==null)truncated=true;for(const e of page.entries){if(result.length>=200){truncated=true;break;}const n=q.path&&q.path!=='.'?q.path+'/'+e.name:e.name;result.push({path:n,type:e.type});if(e.type==='directory'&&q.depth<depth)queue.push({path:n,depth:q.depth+1});}}return {entries:result,truncated:truncated||queue.length>0};}
  async function search(query:string,content=false){
    if(!query||query.length>256)throw Error('Invalid query');const q=query.toLocaleLowerCase(),results: Array<{path:string;line?:number}>=[];let scanned=0,dirs=0,truncated=false;
    const pending=[''];while(pending.length&&results.length<100&&scanned<500&&dirs<100){
      const p=pending.shift()!;dirs++;let cursor:number|null=0;
      do{const page=await list(p,100,cursor??0);for(const e of page.entries){if(results.length>=100||scanned>=500){truncated=true;break;}const n=p?p+'/'+e.name:e.name;if(e.type==='directory'){if(pending.length<100)pending.push(n);else truncated=true;continue;}scanned++;if(!content){if(e.name.toLocaleLowerCase().includes(q))results.push({path:n});}else if((e.bytes??0)<=128*1024){try{const t=utf8.decode(await readBytes(n));const lines=t.split(/\r?\n/);const i=lines.findIndex(l=>l.toLocaleLowerCase().includes(q));if(i>=0)results.push({path:n,line:i+1});}catch{/* binary or unsafe */}}}cursor=page.nextOffset;}while(cursor!==null&&scanned<500&&results.length<100);
    }
    await event(content?'search_content':'search_files','',{scanned});return {results,scanned,truncated:truncated||pending.length>0||results.length>=100||scanned>=500};
  }
  return {list,read,readBinary,info,createDirectory,write,writeBinary,edit,applyPatch,copy,tree,search};
}
