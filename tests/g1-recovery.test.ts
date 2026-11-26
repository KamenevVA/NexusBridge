import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,rm,access} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {makeMvp} from '../src/mvp-core.ts';
import {syntheticGuard,approveSynthetic} from './helpers/local-approval.ts';
const sha=(s:string|Buffer)=>createHash('sha256').update(s).digest('hex');
test('G1 MCP exact-approved move, recoverable trash and replacement rollback',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'g1-recovery-')),root=join(base,'work'),checkpointRoot=join(base,'checkpoints');
  await mkdir(root);await mkdir(checkpointRoot);await mkdir(join(root,'sub'));
  const {guard}=await syntheticGuard(base),logs:object[]=[];
  const m=await makeMvp({root,checkpointRoot,guard,write:true,exec:false,commands:{},assertActive:async()=>{},audit:async e=>{logs.push(e);}});
  const [a,b]=InMemoryTransport.createLinkedPair(),c=new Client({name:'recovery-test',version:'0.1.0'});
  t.after(async()=>{await c.close();await m.stop();await rm(base,{recursive:true,force:true});});await m.server.connect(a);await c.connect(b);
  const raw=(name:string,args:Record<string,unknown>)=>c.callTool({name,arguments:args});
  async function call(name:string,args:Record<string,unknown>){const r=await raw(name,args);assert.equal(r.isError??false,false,JSON.stringify(r));return JSON.parse((r.content as Array<{text:string}>)[0].text);}
  async function approved(name:string,args:Record<string,unknown>){const p=await call(name,args);await approveSynthetic(base,p);return call(name,{...args,approvalId:p.approvalId});}
  const bytes=Buffer.from([0,1,255,128,10]);await writeFile(join(root,'a.bin'),bytes);
  const args={source:'a.bin',destination:'sub/b.bin',expectedHash:sha(bytes)};
  const req=await call('move_file',args);assert.equal(req.status,'awaiting_approval');assert.deepEqual(await readFile(join(root,'a.bin')),bytes);await assert.rejects(access(join(root,'sub/b.bin')),{code:'ENOENT'});
  await approveSynthetic(base,req);
  assert.equal((await raw('move_file',{...args,destination:'changed.bin',approvalId:req.approvalId})).isError,true);
  const moved=await call('move_file',{...args,approvalId:req.approvalId});assert.equal(moved.moved,true);
  assert.equal((await raw('move_file',{...args,approvalId:req.approvalId})).isError,true);
  await assert.rejects(access(join(root,'a.bin')),{code:'ENOENT'});assert.deepEqual(await readFile(join(root,'sub/b.bin')),bytes);assert.deepEqual(await readFile(join(checkpointRoot,moved.checkpointId+'.bak')),bytes);
  await writeFile(join(root,'a.bin'),'conflict');
  const restoreArgs={checkpointId:moved.checkpointId,expectedHash:sha(bytes)};
  const conflict=await call('restore_file',restoreArgs);await approveSynthetic(base,conflict);assert.equal((await raw('restore_file',{...restoreArgs,approvalId:conflict.approvalId})).isError,true);
  assert.equal(await readFile(join(root,'a.bin'),'utf8'),'conflict');assert.deepEqual(await readFile(join(root,'sub/b.bin')),bytes);
  // Remove only this test's known synthetic conflict file through a separate approved trash operation.
  const conflictTrash=await approved('trash_file',{path:'a.bin',expectedHash:sha('conflict')});assert.equal(conflictTrash.trashed,true);
  await approved('restore_file',restoreArgs);assert.deepEqual(await readFile(join(root,'a.bin')),bytes);
  const trash=await approved('trash_file',{path:'a.bin',expectedHash:sha(bytes)});assert.equal(trash.trashed,true);
  await assert.rejects(access(join(root,'a.bin')),{code:'ENOENT'});assert.deepEqual(await readFile(join(checkpointRoot,trash.checkpointId+'.trash')),bytes);
  await approved('restore_file',{checkpointId:trash.checkpointId,expectedHash:sha(bytes)});assert.deepEqual(await readFile(join(root,'a.bin')),bytes);
  const replace=await call('write_binary_file',{path:'a.bin',base64:Buffer.from('next').toString('base64'),expectedHash:sha(bytes)});
  await approved('restore_file',{checkpointId:replace.checkpointId,expectedHash:sha('next')});assert.deepEqual(await readFile(join(root,'a.bin')),bytes);
  assert.ok(logs.some(e=>JSON.stringify(e).includes('restore_file_ok')));
  assert.ok(logs.some(e=>JSON.stringify(e).includes('approval_consumed')));
});
