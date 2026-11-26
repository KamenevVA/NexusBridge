// G1 restricted subprocess prototype. No model-supplied executable, arguments or shell.
import { spawn, type ChildProcess } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import { randomUUID } from 'node:crypto';
type Template={exe:string;args:string[];cwd:string;timeoutMs:number};
type Session={id:string;child:ChildProcess;state:'running'|'completed'|'failed'|'timed_out'|'cancelled';exitCode:number|null;out:Buffer;err:Buffer;truncated:boolean;timer:ReturnType<typeof setTimeout>};
const LIMIT=256*1024;
export async function createProcesses(templates:Readonly<Record<string,Template>>,assertActive:()=>Promise<void>){
  const allowed=new Map<string,Template & {dev:number;ino:number;size:number;mtimeMs:number}>(), sessions=new Map<string,Session>();
  for(const [name,t] of Object.entries(templates)){
    if(!/^[a-zA-Z0-9_-]{1,64}$/.test(name)||!isAbsolute(t.exe)||!isAbsolute(t.cwd)||t.args.length>32||!Number.isSafeInteger(t.timeoutMs)||t.timeoutMs<100||t.timeoutMs>60000)throw Error('Invalid local command template');
    const exe=resolve(t.exe),cwd=resolve(t.cwd),st=await lstat(exe),ct=await lstat(cwd);
    if(!st.isFile()||st.isSymbolicLink()||!ct.isDirectory()||ct.isSymbolicLink()||resolve(await realpath(exe))!==exe||resolve(await realpath(cwd))!==cwd)throw Error('Unsafe executable or working directory');
    allowed.set(name,{exe,cwd,args:[...t.args],timeoutMs:t.timeoutMs,dev:st.dev,ino:st.ino,size:st.size,mtimeMs:st.mtimeMs});
  }
  let starting=0;
  async function start(name:string){
    await assertActive();const t=allowed.get(name);if(!t)throw Error('Command not approved');
    if(sessions.size>=16||starting+Array.from(sessions.values()).filter(s=>s.state==='running').length>=2)throw Error('Process budget exhausted');
    starting++;
    try{
      const st=await lstat(t.exe),ct=await lstat(t.cwd);if(!st.isFile()||st.isSymbolicLink()||st.dev!==t.dev||st.ino!==t.ino||st.size!==t.size||st.mtimeMs!==t.mtimeMs||!ct.isDirectory()||ct.isSymbolicLink()||resolve(await realpath(t.exe))!==t.exe||resolve(await realpath(t.cwd))!==t.cwd)throw Error('Command template changed');await assertActive();
      const env:NodeJS.ProcessEnv={};for(const k of ['SystemRoot','WINDIR','TEMP','TMP'])if(process.env[k])env[k]=process.env[k];
      const child=spawn(t.exe,t.args,{cwd:t.cwd,env,shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});
      const id=randomUUID(),s:Session={id,child,state:'running',exitCode:null,out:Buffer.alloc(0),err:Buffer.alloc(0),truncated:false,timer:setTimeout(()=>{if(s.state==='running'){s.state='timed_out';child.kill();}},t.timeoutMs)};
      sessions.set(id,s);
      function add(channel:'out'|'err',b:Buffer){const remaining=LIMIT-s[channel].length;if(b.length>remaining)s.truncated=true;if(remaining>0)s[channel]=Buffer.concat([s[channel],b.subarray(0,remaining)]);}
      child.stdout?.on('data',(b:Buffer)=>add('out',b));child.stderr?.on('data',(b:Buffer)=>add('err',b));
      child.once('error',()=>{clearTimeout(s.timer);if(s.state==='running')s.state='failed';});
      child.once('close',code=>{clearTimeout(s.timer);s.exitCode=code;if(s.state==='running')s.state=code===0?'completed':'failed';});
      return {id,status:s.state};
    }finally{starting--;}
  }
  function lookup(id:string){const s=sessions.get(id);if(!s)throw Error('Unknown managed process');return s;}
  async function output(id:string,channel:'out'|'err',offset=0,length=12000){
    await assertActive();if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(length)||length<1||length>24000)throw Error('Invalid output cursor');
    const s=lookup(id),b=s[channel];return {status:s.state,exitCode:s.exitCode,base64:b.subarray(offset,offset+length).toString('base64'),nextOffset:Math.min(b.length,offset+length),truncated:s.truncated};
  }
  async function list(){await assertActive();return [...sessions.values()].map(s=>({id:s.id,status:s.state,exitCode:s.exitCode}));}
  async function cancel(id:string){await assertActive();const s=lookup(id);if(s.state==='running'){s.state='cancelled';s.child.kill();}return {status:s.state};}
  function stopAll(){for(const s of sessions.values())if(s.state==='running'){s.state='cancelled';s.child.kill();}}
  let checking=false;const watchdog=setInterval(()=>{if(checking||!Array.from(sessions.values()).some(s=>s.state==='running'))return;checking=true;void assertActive().catch(()=>stopAll()).finally(()=>{checking=false;});},250);watchdog.unref();
  function dispose(){clearInterval(watchdog);stopAll();}
  return {start,output,list,cancel,stopAll,dispose};
}
