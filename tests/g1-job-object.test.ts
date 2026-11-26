import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,readFile,rm,access} from 'node:fs/promises';
import {resolve,join} from 'node:path';
const runner=resolve('.runtime/native/NexusBridge.Job.exe');
const wait=(ms:number)=>new Promise(r=>setTimeout(r,ms));
function launch(cwd:string,code:string,args:string[]=[],timeout=5000){
  const p=spawn(runner,[String(process.pid),String(timeout),process.execPath,cwd,'-e',code,...args],{windowsHide:true,stdio:['pipe','pipe','pipe'],shell:false});
  let out='',err='';p.stdout.on('data',b=>out+=b.toString());p.stderr.on('data',b=>err+=b.toString());
  const done=new Promise<{code:number|null;out:string;err:string}>((ok,fail)=>{p.once('error',fail);p.once('close',code=>ok({code,out,err}));});
  return {p,done,output:()=>out};
}
test('native job helper preserves argument quoting, stdin, stderr and exit code',async t=>{
  const job=launch(process.cwd(),"process.stdin.once('data',b=>{console.log(JSON.stringify([process.argv[1],b.toString()]));console.error('ERR_JOB');process.exitCode=7})",['quote " backslash \\']);
  t.after(()=>{job.p.kill()});job.p.stdin.end('synthetic input');
  const r=await job.done;assert.equal(r.code,7,r.err);assert.deepEqual(JSON.parse(r.out),['quote " backslash \\','synthetic input']);assert.match(r.err,/ERR_JOB/);
});
test('native job kills descendant when wrapper is terminated',async t=>{
  const root=await mkdtemp(join(resolve('.runtime'),'job-tree-'));t.after(()=>rm(root,{recursive:true,force:true}));
  // Both processes are synthetic and confined to the test directory; no arbitrary PID kill.
  const childCode="const fs=require('node:fs');fs.writeFileSync('ready.txt','ready');setTimeout(()=>fs.writeFileSync('escaped.txt','bad'),2600)";
  const parentCode="const {spawn}=require('node:child_process');spawn(process.execPath,['-e',process.argv[1]],{stdio:'ignore',windowsHide:true});setTimeout(()=>{},10000)";
  const job=launch(root,parentCode,[childCode],10000);t.after(()=>{job.p.kill()});job.p.stdin.end();
  let ready=false;for(let i=0;i<60;i++){try{await access(join(root,'ready.txt'));ready=true;break;}catch{await wait(30);}}
  assert.ok(ready,'grandchild failed to start: '+JSON.stringify(await Promise.race([job.done,wait(1)])));
  assert.equal(await readFile(join(root,'ready.txt'),'utf8'),'ready');
  job.p.kill();await job.done;await wait(2850);await assert.rejects(access(join(root,'escaped.txt')),{code:'ENOENT'});
});
test('native independent deadline terminates a long process',async t=>{
  const job=launch(process.cwd(),'setTimeout(()=>{},10000)',[],300);t.after(()=>{job.p.kill()});job.p.stdin.end();
  const r=await job.done;assert.equal(r.code,124,r.err);
});
