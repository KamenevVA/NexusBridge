// G1 workspace prototype. Requires an OS-isolated, owner-selected root; not an OS sandbox.
import { createHash, randomUUID } from 'node:crypto';
import { lstat, realpath, open, opendir } from 'node:fs/promises';
import { execFile } from 'node:child_process';

import { fileURLToPath } from 'node:url';
import { resolve, join, relative, isAbsolute } from 'node:path';
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
export async function createWorkspace(rootPath:string, options:{write:boolean;checkpointRoot?:string;allowTransfer?:boolean;assertActive:()=>Promise<void>;audit:(e:object)=>Promise<void>}){
  const root=resolve(rootPath);
  const rootStat=await lstat(root);
  if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||resolve(await realpath(root))!==root)throw Error('Unsafe workspace root');
  const checkpointRoot=options.checkpointRoot?resolve(options.checkpointRoot):undefined;
  const checkpointStat=checkpointRoot?await lstat(checkpointRoot):undefined;
  const outside=(a:string,b:string)=>{const r=relative(a,b);return isAbsolute(r)||r==='..'||r.startsWith('..'+(process.platform==='win32'?'\\':'/'));};
  if(checkpointRoot&&(!checkpointStat?.isDirectory()||checkpointStat.isSymbolicLink()||resolve(await realpath(checkpointRoot))!==checkpointRoot||!outside(root,checkpointRoot)||!outside(checkpointRoot,root)))throw Error('Checkpoint root must be separate');
  async function guardCheckpoint(){if(!checkpointRoot||!checkpointStat)throw Error('Checkpoint store required for replacement');const s=await lstat(checkpointRoot);if(!s.isDirectory()||s.isSymbolicLink()||!same(s,checkpointStat)||resolve(await realpath(checkpointRoot))!==checkpointRoot)throw Error('Checkpoint store changed');return checkpointRoot;}
  const nativePath=resolve(fileURLToPath(new URL('../.runtime/native/NexusBridge.FileMove.exe',import.meta.url)));
  let nativeIdentity:{dev:number;ino:number;size:number;mtimeMs:number}|undefined,nativeHash:string|undefined;
  async function privateRead(p:string,max:number){
    const s=await lstat(p);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>max||resolve(await realpath(p))!==p)throw Error('Unsafe private file');
    const f=await open(p,'r');try{const before=await f.stat();if(!same(s,before)||before.size!==s.size||before.nlink!==1)throw Error('Private file changed');
      const buf=Buffer.alloc(before.size);let offset=0;while(offset<buf.length){const r=await f.read(buf,offset,buf.length-offset,offset);if(!r.bytesRead)throw Error('Private file truncated');offset+=r.bytesRead;}
      const after=await f.stat(),check=await lstat(p);if(!same(before,after)||!same(before,check)||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.nlink!==1||check.nlink!==1)throw Error('Private file changed');
      return buf;
    }finally{await f.close();}
  }
  if(process.platform!=='win32'||process.arch!=='x64')throw Error('Windows x64 native file boundary required');
  if(options.allowTransfer&&(!options.write||!checkpointRoot))throw Error('Transfer requires protected checkpoint store');
  nativeIdentity=await lstat(nativePath);nativeHash=digest(await privateRead(nativePath,1024*1024));
  async function nativeCall(args:string[],input?:Buffer,write=false){
    if(!nativeIdentity||!nativeHash)throw Error('Native file boundary not enabled');
    const st=await lstat(nativePath);
    if(!same(st,nativeIdentity)||st.size!==nativeIdentity.size||st.mtimeMs!==nativeIdentity.mtimeMs||digest(await privateRead(nativePath,1024*1024))!==nativeHash)throw Error('Native file helper changed');
    await active(write);
    const env:NodeJS.ProcessEnv={};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
    const out=await new Promise<Buffer>((ok,fail)=>{
      const child=execFile(nativePath,args,{shell:false,windowsHide:true,timeout:15000,maxBuffer:5*1024*1024,encoding:'buffer',env,cwd:root},(e,stdout)=>{
        if(e)fail(Error('Native file operation refused or outcome unknown'));else ok(stdout);
      });
      child.stdin?.on('error',()=>{});child.stdin?.end(input);
    });
    await active(write);return out;
  }
  async function nativeMove(source:string,destination:string,expectedHash:string){
    if(!options.allowTransfer)throw Error('Native transfer not enabled');
    await guardCheckpoint();
    const r=await nativeCall([source,destination,expectedHash],undefined,true);
    if(r.toString('utf8').trim()!=='MOVE_OK')throw Error('Unknown transfer outcome');
  }
  async function nativeWrite(path:string,bytes:Buffer,expectedHash:string|null,backup=''){
    const hash=digest(bytes),r=await nativeCall(['io-write',path,expectedHash??'new',hash,backup],bytes,true);
    if(r.toString('utf8').trim()!=='WRITE_OK')throw Error('Unknown write outcome');
  }
  type Manifest={v:1;kind:'move'|'trash'|'replace';path:string;sha256:string;destination?:string;newSha256?:string};
  const validHash=(x:unknown):x is string=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
  async function privateWrite(name:string,bytes:Buffer){
    const store=await guardCheckpoint(),p=join(store,name);
    let count=0,total=0;
    for await(const entry of await opendir(store)){
      if(++count>=512)throw Error('Checkpoint count budget exhausted');
      const st=await lstat(join(store,entry.name));
      if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)throw Error('Unsafe checkpoint entry');
      total+=st.size;if(total+bytes.length>128*1024*1024)throw Error('Checkpoint byte budget exhausted');
    }
    await guardCheckpoint();const f=await open(p,'wx',0o600);
    try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}
    await guardCheckpoint();
  }
  async function saveManifest(id:string,m:Manifest){await privateWrite(id+'.json',Buffer.from(JSON.stringify(m)+'\n','utf8'));}
  async function loadManifest(id:string){
    if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id))throw Error('Invalid checkpoint ID');
    const store=await guardCheckpoint(),bytes=await privateRead(join(store,id+'.json'),4096);await guardCheckpoint();
    const m=JSON.parse(utf8.decode(bytes)) as Manifest;
    if(!m||m.v!==1||typeof m.path!=='string'||!parts(m.path).length||!validHash(m.sha256)||!['move','trash','replace'].includes(m.kind))throw Error('Invalid checkpoint manifest');
    const keys=Object.keys(m).sort().join(',');
    if(m.kind==='move'&&(keys!=='destination,kind,path,sha256,v'||typeof m.destination!=='string'||!parts(m.destination).length))throw Error('Invalid move manifest');
    if(m.kind==='trash'&&keys!=='kind,path,sha256,v')throw Error('Invalid trash manifest');
    if(m.kind==='replace'&&(keys!=='kind,newSha256,path,sha256,v'||!validHash(m.newSha256)))throw Error('Invalid replacement manifest');
    return {m,manifestHash:digest(bytes),store};
  }
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
    const bytes=await nativeCall(['io-read',x.path]);if(bytes.length>maxBytes)throw Error('Native file size exceeded');return bytes;
  }
  async function event(action:string,path:string,detail:object={}){await options.audit({utc:new Date().toISOString(),action,path,...detail});}
  let queue=Promise.resolve();
  function serial<T>(fn:()=>Promise<T>){const next=queue.then(fn);queue=next.then(()=>{},()=>{});return next;}
  async function list(p='',limit=100,offset=0){
    if(!Number.isSafeInteger(limit)||limit<1||limit>200||!Number.isSafeInteger(offset)||offset<0)throw Error('Invalid pagination');
    const x=await inspect(p);if(!x.st?.isDirectory())throw Error('Not a directory');
    const raw=(await nativeCall(['io-list',x.path])).toString('utf8').trimEnd().split(/\r?\n/);
    const header=raw.shift();if(header!=='LIST_0'&&header!=='LIST_1')throw Error('Invalid native list');
    const entries:Array<{name:string;type:'directory'|'file';bytes?:number}>=[];
    for(const line of raw){const [name64,type,size,...extra]=line.split('\t');if(extra.length||!name64||!['D','F'].includes(type)||! /^\d+$/.test(size))throw Error('Invalid native list entry');
      const name=utf8.decode(Buffer.from(name64,'base64')),bytes=Number(size);if(!Number.isSafeInteger(bytes)||bytes<0)throw Error('Invalid native file size');
      try{if(parts(name).length!==1)continue;}catch{continue;}
      entries.push({name,type:type==='D'?'directory':'file',bytes:type==='F'?bytes:undefined});
    }
    entries.sort((a,b)=>a.name.localeCompare(b.name));await event('list_directory',p);
    return {entries:entries.slice(offset,offset+limit),nextOffset:offset+limit<entries.length?offset+limit:null,truncated:header==='LIST_1'};
  }
  async function read(p:string,offset=0,length=12000){
    if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(length)||length<1||length>24000)throw Error('Invalid pagination');
    const bytes=await readBytes(p);const text=utf8.decode(bytes);const sha256=digest(bytes);
    await event('read_file',p,{sha256});
    return {text:text.slice(offset,offset+length),sha256,bytes:bytes.length,nextOffset:offset+length<text.length?offset+length:null};
  }
  async function info(p:string){const x=await inspect(p);if(!x.st)throw Error('Missing object');const raw=(await nativeCall(['io-stat',x.path])).toString('utf8').trim().split('\t');if(raw.length!==2||!['D','F'].includes(raw[0]))throw Error('Invalid native metadata');const data=raw[0]==='F'?await readBytes(p):undefined;const sha256=data?digest(data):undefined;await event('get_file_info',p,{sha256});return {type:raw[0]==='D'?'directory':'file',bytes:data?.length??0,sha256};}
  async function createDirectory(p:string){return serial(async()=>{await active(true);if(!parts(p).length)throw Error('Root denied');const x=await inspect(p,true);if(x.st)throw Error('Already exists');await event('create_directory_attempt',p);const r=await nativeCall(['io-mkdir',x.path],undefined,true);if(r.toString('utf8').trim()!=='MKDIR_OK')throw Error('Unknown create directory outcome');await inspect(p);await event('create_directory_ok',p);return {created:true};});}
  async function writeBytes(p:string,bytes:Buffer,expectedHash:string|null){return serial(async()=>{
    await active(true);if(!parts(p).length)throw Error('Root denied');
    if(bytes.length>maxBytes)throw Error('File too large');
    const x=await inspect(p,true);let prior:Buffer|undefined;
    if(x.st){if(!x.st.isFile()||expectedHash===null)throw Error('Conflict: explicit hash required');prior=await readBytes(p);if(digest(prior)!==expectedHash)throw Error('Conflict: hash mismatch');}
    else if(expectedHash!==null)throw Error('Conflict: file missing');
    const sha256=digest(bytes);await event('write_file_attempt',p,{expectedHash,sha256});
    if(prior){
      const store=await guardCheckpoint(),checkpointId=randomUUID(),backup=join(store,checkpointId+'.bak');
      await privateWrite(checkpointId+'.bak',prior);
      await saveManifest(checkpointId,{v:1,kind:'replace',path:p,sha256:digest(prior),newSha256:sha256});
      await event('checkpoint_created',p,{checkpointId,sha256:expectedHash});
      try{
        await guardCheckpoint();await nativeWrite(x.path,bytes,expectedHash,backup);
        if(digest(await readBytes(p))!==sha256)throw Error('Unknown write outcome');
        await event('write_file_ok',p,{sha256,checkpointId});return {sha256,bytes:bytes.length,checkpointId};
      }catch{throw Error('Write refused or unknown outcome; inspect checkpoint '+checkpointId+' before retry');}
    }
    await nativeWrite(x.path,bytes,null);
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
  async function move(source:string,destination:string,expectedHash:string){return serial(async()=>{
    await active(true);if(!options.allowTransfer||!parts(source).length||!parts(destination).length||!validHash(expectedHash))throw Error('Move denied');
    const src=await inspect(source),dst=await inspect(destination,true);
    if(!src.st?.isFile()||dst.st)throw Error('Source or destination conflict');
    const bytes=await readBytes(source);if(digest(bytes)!==expectedHash)throw Error('Conflict: hash mismatch');
    const checkpointId=randomUUID();await privateWrite(checkpointId+'.bak',bytes);
    await saveManifest(checkpointId,{v:1,kind:'move',path:source,destination,sha256:expectedHash});
    await event('move_file_attempt',source,{expectedHash,checkpointId});
    try{await nativeMove(src.path,dst.path,expectedHash);}catch{throw Error('Move refused or unknown outcome; inspect checkpoint '+checkpointId+' before retry');}
    if((await inspect(source,true)).st||digest(await readBytes(destination))!==expectedHash)throw Error('Unknown move outcome');
    await event('move_file_ok',destination,{sha256:expectedHash,checkpointId});return {sha256:expectedHash,checkpointId,moved:true};
  });}
  async function trash(p:string,expectedHash:string){return serial(async()=>{
    await active(true);if(!options.allowTransfer||!parts(p).length||!validHash(expectedHash))throw Error('Trash denied');
    const src=await inspect(p);if(!src.st?.isFile()||digest(await readBytes(p))!==expectedHash)throw Error('Conflict: hash mismatch');
    const store=await guardCheckpoint(),checkpointId=randomUUID();
    await privateWrite(checkpointId+'.trash',await readBytes(p));
    await saveManifest(checkpointId,{v:1,kind:'trash',path:p,sha256:expectedHash});
    await event('trash_file_attempt',p,{expectedHash,checkpointId});
    const dest=join(store,checkpointId+'.trash');try{const r=await nativeCall(['io-trash',src.path,expectedHash,dest],undefined,true);if(r.toString('utf8').trim()!=='TRASH_OK')throw Error('Unknown trash outcome');}catch{throw Error('Trash refused or unknown outcome; inspect checkpoint '+checkpointId+' before retry');}
    if((await inspect(p,true)).st||digest(await privateRead(dest,maxBytes))!==expectedHash)throw Error('Unknown trash outcome');
    await event('trash_file_ok',p,{sha256:expectedHash,checkpointId});return {sha256:expectedHash,checkpointId,trashed:true};
  });}
  async function currentHash(p:string){
    const x=await inspect(p,true);if(!x.st)return null;if(!x.st.isFile())throw Error('Checkpoint target is not a regular file');return digest(await readBytes(p));
  }
  async function checkpointInfo(checkpointId:string){
    await active();if(!options.allowTransfer)throw Error('Checkpoint access denied');
    const {m,manifestHash,store}=await loadManifest(checkpointId),sourceHash=await currentHash(m.path);
    const destinationHash=m.kind==='move'?await currentHash(m.destination!):null;
    let backupVerified=false;
    try{backupVerified=digest(await privateRead(join(store,checkpointId+(m.kind==='trash'?'.trash':'.bak')),maxBytes))===m.sha256;}catch{}
    await event('get_checkpoint_info',m.path,{checkpointId,sha256:manifestHash});
    return {...m,checkpointId,manifestHash,sourceHash,destinationHash,backupVerified};
  }
  async function describeRestore(checkpointId:string){
    await active(true);if(!options.allowTransfer)throw Error('Restore denied');
    const {m,manifestHash}=await loadManifest(checkpointId);return {...m,checkpointId,manifestHash};
  }
  async function restore(checkpointId:string,expectedHash:string|null,manifestHash:string){
    await active(true);if(!options.allowTransfer||(expectedHash!==null&&!validHash(expectedHash))||!validHash(manifestHash))throw Error('Restore denied');
    const initial=await loadManifest(checkpointId);if(initial.manifestHash!==manifestHash)throw Error('Checkpoint changed');
    if(initial.m.kind==='replace'||initial.m.kind==='trash'){
      const m=initial.m;
      if(m.kind==='replace'&&expectedHash!==null&&expectedHash!==m.newSha256)throw Error('Conflict: changed since checkpoint');
      if(m.kind==='trash'&&expectedHash!==m.sha256)throw Error('Trash checkpoint digest mismatch');
      const backup=await privateRead(join(initial.store,checkpointId+(m.kind==='trash'?'.trash':'.bak')),maxBytes);if(digest(backup)!==m.sha256)throw Error('Checkpoint digest mismatch');
      await event('restore_file_attempt',m.path,{expectedHash,checkpointId});
      const r=await writeBytes(m.path,backup,m.kind==='trash'?null:expectedHash);
      await event('restore_file_ok',m.path,{sha256:r.sha256,checkpointId});return {...r,checkpointId,restored:true};
    }
    return serial(async()=>{
      await active(true);const {m,store,manifestHash:actual}=await loadManifest(checkpointId);
      if(actual!==manifestHash||m.kind!=='move'||expectedHash!==m.sha256)throw Error('Checkpoint changed or hash conflict');
      const dst=await inspect(m.path,true);if(dst.st)throw Error('Restore destination already exists');
      const x=await inspect(m.destination!,true);
      await event('restore_file_attempt',m.path,{expectedHash,checkpointId});
      if(x.st){
        if(!x.st.isFile()||digest(await readBytes(m.destination!))!==m.sha256)throw Error('Move source changed');
        await nativeMove(x.path,dst.path,m.sha256);
      }else{
        const backup=await privateRead(join(store,checkpointId+'.bak'),maxBytes);if(digest(backup)!==m.sha256)throw Error('Checkpoint digest mismatch');
        await nativeWrite(dst.path,backup,null);
      }
      if(digest(await readBytes(m.path))!==m.sha256)throw Error('Unknown restore outcome');
      await event('restore_file_ok',m.path,{sha256:m.sha256,checkpointId});return {sha256:m.sha256,checkpointId,restored:true};
    });
  }
  async function tree(p:string,depth=2){if(!Number.isSafeInteger(depth)||depth<0||depth>5)throw Error('Invalid tree depth');const result:Array<{path:string;type:string}>=[];const queue=[{path:p,depth:0}];let truncated=false;while(queue.length&&result.length<200){const q=queue.shift()!;const page=await list(q.path,200,0);if(page.nextOffset!==null||page.truncated)truncated=true;for(const e of page.entries){if(result.length>=200){truncated=true;break;}const n=q.path&&q.path!=='.'?q.path+'/'+e.name:e.name;result.push({path:n,type:e.type});if(e.type==='directory'&&q.depth<depth)queue.push({path:n,depth:q.depth+1});}}return {entries:result,truncated:truncated||queue.length>0};}
  async function search(query:string,content=false){
    if(!query||query.length>256)throw Error('Invalid query');const q=query.toLocaleLowerCase(),results: Array<{path:string;line?:number}>=[];let scanned=0,dirs=0,truncated=false;
    const pending=[''];while(pending.length&&results.length<100&&scanned<500&&dirs<100){
      const p=pending.shift()!;dirs++;let cursor:number|null=0;
      do{const page=await list(p,100,cursor??0);if(page.truncated)truncated=true;for(const e of page.entries){if(results.length>=100||scanned>=500){truncated=true;break;}const n=p?p+'/'+e.name:e.name;if(e.type==='directory'){if(pending.length<100)pending.push(n);else truncated=true;continue;}scanned++;if(!content){if(e.name.toLocaleLowerCase().includes(q))results.push({path:n});}else if((e.bytes??0)<=128*1024){try{const t=utf8.decode(await readBytes(n));const lines=t.split(/\r?\n/);const i=lines.findIndex(l=>l.toLocaleLowerCase().includes(q));if(i>=0)results.push({path:n,line:i+1});}catch{/* binary or unsafe */}}}cursor=page.nextOffset;}while(cursor!==null&&scanned<500&&results.length<100);
    }
    await event(content?'search_content':'search_files','',{scanned});return {results,scanned,truncated:truncated||pending.length>0||results.length>=100||scanned>=500};
  }
  return {list,read,readBinary,info,createDirectory,write,writeBinary,edit,applyPatch,copy,move,trash,checkpointInfo,describeRestore,restore,tree,search};
}
