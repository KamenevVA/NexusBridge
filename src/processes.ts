// G1 restricted subprocess prototype. No model-supplied executable, arguments or shell.
// Native Windows job boundary controls process lifetime, not filesystem/network permissions.
import {spawn,type ChildProcess} from 'node:child_process';
import {lstat,realpath,readFile} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID,createHash} from 'node:crypto';
type Template={exe:string;args:string[];cwd:string;timeoutMs:number;input?:boolean};
type Identity={dev:number;ino:number;size:number;mtimeMs:number};
type Session={id:string;child:ChildProcess;state:'running'|'completed'|'failed'|'timed_out'|'cancelled';exitCode:number|null;out:Buffer;err:Buffer;truncated:boolean;timer:ReturnType<typeof setTimeout>;inputAllowed:boolean;inputBytes:number;inputClosed:boolean;inputBusy:boolean};
const LIMIT=256*1024,INPUT_LIMIT=16*1024;
const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
const same=(a:Identity,b:Identity)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs;
export async function createProcesses(templates:Readonly<Record<string,Template>>,assertActive:()=>Promise<void>){
  const allowed=new Map<string,Template&{identity:Identity;cwdIdentity:{dev:number;ino:number}}>(),sessions=new Map<string,Session>();
  const helper=resolve(fileURLToPath(new URL('../.runtime/native/NexusBridge.Job.exe',import.meta.url)));
  let helperIdentity:Identity|undefined,helperHash:string|undefined;
  if(Object.keys(templates).length){
    if(process.platform!=='win32'||process.arch!=='x64')throw Error('Windows x64 native executor required');
    const st=await lstat(helper);
    if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||resolve(await realpath(helper))!==helper||st.size>1024*1024)throw Error('Unsafe native job helper');
    helperIdentity=st;helperHash=sha(await readFile(helper));
  }
  for(const [name,t] of Object.entries(templates)){
    if(!/^[a-zA-Z0-9_-]{1,64}$/.test(name)||!isAbsolute(t.exe)||!isAbsolute(t.cwd)||t.args.length>32||
      t.args.some(x=>x.length>4096||x.includes('\0'))||!Number.isSafeInteger(t.timeoutMs)||t.timeoutMs<100||t.timeoutMs>60000)throw Error('Invalid local command template');
    const exe=resolve(t.exe),cwd=resolve(t.cwd),st=await lstat(exe),ct=await lstat(cwd);
    if(!st.isFile()||st.isSymbolicLink()||!ct.isDirectory()||ct.isSymbolicLink()||resolve(await realpath(exe))!==exe||resolve(await realpath(cwd))!==cwd||!exe.toLowerCase().endsWith('.exe'))throw Error('Unsafe executable or working directory');
    allowed.set(name,{exe,cwd,args:[...t.args],timeoutMs:t.timeoutMs,input:t.input===true,identity:st,cwdIdentity:ct});
  }
  let starting=0,disposed=false;
  async function active(){if(disposed)throw Error('Process executor stopped');await assertActive();}
  async function start(name:string){
    await active();const t=allowed.get(name);if(!t||!helperIdentity||!helperHash)throw Error('Command not approved');
    if(sessions.size+starting>=16||starting+[...sessions.values()].filter(s=>s.state==='running').length>=2)throw Error('Process budget exhausted');
    starting++;
    try{
      const st=await lstat(t.exe),ct=await lstat(t.cwd),hs=await lstat(helper);
      if(!st.isFile()||st.isSymbolicLink()||!same(st,t.identity)||!ct.isDirectory()||ct.isSymbolicLink()||ct.dev!==t.cwdIdentity.dev||ct.ino!==t.cwdIdentity.ino||
        resolve(await realpath(t.exe))!==t.exe||resolve(await realpath(t.cwd))!==t.cwd||!hs.isFile()||hs.isSymbolicLink()||hs.nlink!==1||!same(hs,helperIdentity)||resolve(await realpath(helper))!==helper||sha(await readFile(helper))!==helperHash)throw Error('Command template or job helper changed');
      await active();
      const env:NodeJS.ProcessEnv={};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
      const child=spawn(helper,[String(process.pid),String(t.timeoutMs),t.exe,t.cwd,...t.args],{cwd:t.cwd,env,shell:false,windowsHide:true,stdio:[t.input?'pipe':'ignore','pipe','pipe']});
      const id=randomUUID(),s:Session={id,child,state:'running',exitCode:null,out:Buffer.alloc(0),err:Buffer.alloc(0),truncated:false,inputAllowed:t.input===true,inputBytes:0,inputClosed:!t.input,inputBusy:false,
        timer:setTimeout(()=>{if(s.state==='running'){s.state='timed_out';child.kill();}},t.timeoutMs+250)};
      sessions.set(id,s);
      function add(channel:'out'|'err',b:Buffer){const remaining=LIMIT-s[channel].length;if(b.length>remaining)s.truncated=true;if(remaining>0)s[channel]=Buffer.concat([s[channel],b.subarray(0,remaining)]);}
      child.stdout?.on('data',(b:Buffer)=>add('out',b));child.stderr?.on('data',(b:Buffer)=>add('err',b));child.stdin?.on('error',()=>{s.inputClosed=true;});
      child.once('error',()=>{clearTimeout(s.timer);if(s.state==='running')s.state='failed';});
      child.once('close',code=>{clearTimeout(s.timer);s.inputClosed=true;s.exitCode=code;if(s.state==='running')s.state=code===0?'completed':code===124?'timed_out':'failed';});
      return {id,status:s.state};
    }finally{starting--;}
  }
  function describe(name:string){const t=allowed.get(name);if(!t)throw Error('Command not approved');return {template:name,exe:t.exe,args:[...t.args],cwd:t.cwd,timeoutMs:t.timeoutMs,input:t.input===true};}
  function lookup(id:string){const s=sessions.get(id);if(!s)throw Error('Unknown managed process');return s;}
  async function output(id:string,channel:'out'|'err',offset=0,length=12000){
    await active();if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(length)||length<1||length>24000)throw Error('Invalid output cursor');
    const s=lookup(id),b=s[channel];return {status:s.state,exitCode:s.exitCode,base64:b.subarray(offset,offset+length).toString('base64'),nextOffset:Math.min(b.length,offset+length),truncated:s.truncated};
  }
  async function input(id:string,text:string,close=false){
    await active();const s=lookup(id),b=Buffer.from(text,'utf8');
    if(!s.inputAllowed||s.inputClosed||s.inputBusy||s.state!=='running'||!s.child.stdin||b.length>4096||s.inputBytes+b.length>INPUT_LIMIT||(!b.length&&!close))throw Error('Process input denied or budget exhausted');
    s.inputBusy=true;
    try{
      await active();if(s.state!=='running'||s.inputClosed)throw Error('Process no longer accepts input');
      s.inputBytes+=b.length;
      const stream=s.child.stdin;
      await new Promise<void>((ok,fail)=>{
        let done=false;
        const finish=(e?:Error)=>{if(done)return;done=true;clearTimeout(timer);stream.off('error',onError);stream.off('close',onClose);if(e){s.inputClosed=true;stream.destroy();fail(e);}else ok();};
        const onError=(e:Error)=>finish(e),onClose=()=>finish(Error('Process input stream closed'));
        const timer=setTimeout(()=>finish(Error('Process input timed out')),1000);
        stream.once('error',onError);stream.once('close',onClose);
        if(close){s.inputClosed=true;stream.end(b,()=>finish());}else stream.write(b,e=>finish(e??undefined));
      });
      return {acceptedBytes:b.length,inputClosed:s.inputClosed};
    }finally{s.inputBusy=false;}
  }
  async function list(){await active();return [...sessions.values()].map(s=>({id:s.id,status:s.state,exitCode:s.exitCode,inputAllowed:s.inputAllowed&&!s.inputClosed}));}
  async function cancel(id:string){await active();const s=lookup(id);if(s.state==='running'){s.state='cancelled';s.child.kill();}return {status:s.state};}
  function stopAll(){for(const s of sessions.values())if(s.state==='running'){s.state='cancelled';s.child.kill();}}
  let checking=false;const watchdog=setInterval(()=>{if(checking||![...sessions.values()].some(s=>s.state==='running'))return;checking=true;void active().catch(()=>stopAll()).finally(()=>{checking=false;});},250);watchdog.unref();
  function dispose(){disposed=true;clearInterval(watchdog);stopAll();}
  return {start,describe,output,input,list,cancel,stopAll,dispose};
}
