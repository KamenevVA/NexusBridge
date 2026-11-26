import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,rm,access,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {makeMvp} from '../src/mvp-core.ts';
import {syntheticGuard,approveSynthetic} from './helpers/local-approval.ts';
const sha=(b:string|Buffer)=>createHash('sha256').update(b).digest('hex');
test('G1 interrupted native replacement recovers from durable checkpoint after process exit',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'g1-interrupt-')),root=join(base,'work'),checkpointRoot=join(base,'checkpoints');
  await mkdir(root);await mkdir(checkpointRoot);
  t.after(()=>rm(base,{recursive:true,force:true}));
  // A separate synthetic test-only build exits between the two native renames.
  const exe=join(base,'fault-only.exe'),compiler=join(process.env.SystemRoot??'C:\\Windows','Microsoft.NET','Framework64','v4.0.30319','csc.exe');
  const build=spawnSync(compiler,['/nologo','/target:exe','/platform:x64','/define:NB_TEST_FAULT','/out:'+exe,resolve('native/FileMove.cs')],{windowsHide:true,encoding:'utf8',timeout:15000});
  assert.equal(build.status,0,build.stdout+build.stderr);
  const original=Buffer.from('original\r\n'),next=Buffer.from('updated'),id=randomUUID(),path='interrupted.txt',target=join(root,path),backup=join(checkpointRoot,id+'.bak');
  await writeFile(target,original);await writeFile(backup,original);
  await writeFile(join(checkpointRoot,id+'.json'),JSON.stringify({v:1,kind:'replace',path,sha256:sha(original),newSha256:sha(next)})+'\n');
  const r=spawnSync(exe,['io-write',target,sha(original),sha(next),backup],{input:next,windowsHide:true,timeout:10000});
  assert.equal(r.status,73,r.stderr?.toString());await assert.rejects(access(target),{code:'ENOENT'});
  assert.deepEqual(await readFile(backup),original);assert.ok((await readdir(root)).some(n=>n.startsWith('.nb-tmp-old-')));
  // Fresh core opens the same durable checkpoint store; no replay of the failed write.
  const {guard}=await syntheticGuard(base);
  const m=await makeMvp({root,checkpointRoot,guard,write:true,exec:false,commands:{},assertActive:async()=>{},audit:async()=>{}});
  const [a,b]=InMemoryTransport.createLinkedPair(),c=new Client({name:'interruption-test',version:'0.1.0'});
  t.after(async()=>{await c.close();await m.stop();});await m.server.connect(a);await c.connect(b);
  async function call(name:string,args:Record<string,unknown>){const r=await c.callTool({name,arguments:args});assert.equal(r.isError??false,false,JSON.stringify(r));return JSON.parse((r.content as Array<{text:string}>)[0].text);}
  const info=await call('get_checkpoint_info',{checkpointId:id});assert.equal(info.sourceHash,null);assert.equal(info.backupVerified,true);
  const args={checkpointId:id,expectedHash:null},request=await call('restore_file',args);
  await approveSynthetic(base,request);
  assert.equal((await call('restore_file',{...args,approvalId:request.approvalId})).restored,true);
  assert.deepEqual(await readFile(target),original);assert.deepEqual(await readFile(backup),original);
  const list=await call('list_directory',{path:''});assert.ok(!list.entries.some((e:{name:string})=>e.name.startsWith('.nb-tmp-')));
  // Subsequent recovery must not overwrite an existing conflicting file.
  const repeat=await call('restore_file',args);await approveSynthetic(base,repeat);
  assert.equal((await c.callTool({name:'restore_file',arguments:{...args,approvalId:repeat.approvalId}})).isError,true);
  assert.deepEqual(await readFile(target),original);
});
