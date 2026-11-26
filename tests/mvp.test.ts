import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, symlink, link, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { makeMvp } from '../src/mvp-core.ts';
import {syntheticGuard,approveSynthetic} from './helpers/local-approval.ts';

test('G1 isolated workspace MCP and fixed command lifecycle',async t=>{
  await mkdir(join(process.cwd(),'.runtime'),{recursive:true});
  const base=await mkdtemp(join(process.cwd(),'.runtime','mvp-')),root=join(base,'workspace'),outside=join(base,'outside'),checkpointRoot=join(base,'checkpoints');
  await mkdir(root);await mkdir(outside);await mkdir(checkpointRoot);await writeFile(join(outside,'sentinel.txt'),'outside');
  await writeFile(join(root,'.env'),'synthetic secret');await writeFile(join(root,'existing.txt'),'unchanged');
  await symlink(outside,join(root,'junction'),'junction');await link(join(outside,'sentinel.txt'),join(root,'hardlink.txt'));
  const {guard}=await syntheticGuard(base);const logs:object[]=[];let active=true;
  const m=await makeMvp({root,checkpointRoot,guard,write:true,exec:true,assertActive:async()=>{if(!active)throw Error('Revoked');},audit:async e=>{logs.push(e);},commands:{hello:{exe:process.execPath,args:['-e','process.stdout.write("NB_MVP_OK");process.stderr.write("ERR_TEST");'],cwd:root,timeoutMs:5000},slow:{exe:process.execPath,args:['-e','setTimeout(()=>{},10000)'],cwd:root,timeoutMs:150}}});
  const [a,b]=InMemoryTransport.createLinkedPair();const c=new Client({name:'mvp-test',version:'0.1.0'});t.after(async()=>{await c.close();await m.stop();});
  await m.server.connect(a);await c.connect(b);
  async function raw(name:string,args:Record<string,unknown>={}){return c.callTool({name,arguments:args});}
  async function call(name:string,args:Record<string,unknown>={}){let r=await raw(name,args);assert.equal(r.isError??false,false,JSON.stringify(r));let v=JSON.parse((r.content as Array<{text:string}>)[0].text);if(name==='start_process'&&v.status==='awaiting_approval'){await approveSynthetic(base,v);r=await raw(name,{...args,approvalId:v.approvalId});assert.equal(r.isError??false,false,JSON.stringify(r));v=JSON.parse((r.content as Array<{text:string}>)[0].text);}return v;}
  assert.equal((await c.listTools()).tools.length,24);
  await call('create_directory',{path:'Проект'});
  const content='Привет\r\nNexusBridge\r\n';const hash=createHash('sha256').update(content).digest('hex');
  assert.equal((await call('write_file',{path:'Проект/тест.txt',content,expectedHash:null})).sha256,hash);
  assert.equal(await readFile(join(root,'Проект','тест.txt'),'utf8'),content);
  const r=await call('read_file',{path:'Проект/тест.txt',length:6});assert.equal(r.text,'Привет');assert.equal(r.sha256,hash);assert.equal(r.nextOffset,6);
  assert.equal((await call('get_file_info',{path:'Проект/тест.txt'})).sha256,hash);
  assert.equal((await call('search_content',{query:'NexusBridge'})).results[0].path,'Проект/тест.txt');
  assert.equal((await call('search_files',{query:'тест'})).results[0].path,'Проект/тест.txt');
  const ls=await call('list_directory',{path:''});assert.ok(!ls.entries.some((e:{name:string})=>['.env','junction','hardlink.txt'].includes(e.name)));
  for(const path of ['../outside/sentinel.txt','junction/sentinel.txt','hardlink.txt','.env','C:/Windows/win.ini','existing.txt:stream','CON','existing.txt.'])assert.equal((await raw('read_file',{path})).isError,true,path);
  assert.equal((await raw('write_file',{path:'existing.txt',content:'overwrite',expectedHash:null})).isError,true);
  assert.equal(await readFile(join(root,'existing.txt'),'utf8'),'unchanged');
  const oldHash=createHash('sha256').update('unchanged').digest('hex');
  const updated=await call('edit_file',{path:'existing.txt',oldText:'unchanged',newText:'edited',expectedHash:oldHash});assert.equal(await readFile(join(root,'existing.txt'),'utf8'),'edited');assert.equal(await readFile(join(checkpointRoot,updated.checkpointId+'.bak'),'utf8'),'unchanged');
  assert.equal((await raw('write_file',{path:'existing.txt',content:'conflict',expectedHash:oldHash})).isError,true);
  await call('copy_file',{source:'Проект/тест.txt',destination:'copy.txt'});assert.equal(await readFile(join(root,'copy.txt'),'utf8'),content);
  assert.equal((await call('read_multiple_files',{paths:['copy.txt','existing.txt']})).length,2);assert.ok((await call('directory_tree',{path:'',depth:2})).entries.some((e:{path:string})=>e.path==='Проект/тест.txt'));
  assert.equal((await raw('start_process',{template:'arbitrary'})).isError,true);
  const s=await call('start_process',{template:'hello'});
  let out;for(let i=0;i<50;i++){out=await call('read_process_output',{id:s.id,channel:'out'});if(out.status!=='running')break;await new Promise(r=>setTimeout(r,40));}
  assert.equal(out.status,'completed');assert.equal(out.exitCode,0);assert.equal(Buffer.from(out.base64,'base64').toString(),'NB_MVP_OK');
  const err=await call('read_process_output',{id:s.id,channel:'err'});assert.equal(Buffer.from(err.base64,'base64').toString(),'ERR_TEST');
  const slow=await call('start_process',{template:'slow'});await new Promise(r=>setTimeout(r,350));assert.equal((await call('read_process_output',{id:slow.id,channel:'out'})).status,'timed_out');
  active=false;assert.equal((await raw('read_file',{path:'existing.txt'})).isError,true);assert.equal((await raw('start_process',{template:'hello'})).isError,true);
  assert.ok(logs.some(e=>JSON.stringify(e).includes(hash)));assert.ok(!JSON.stringify(logs).includes(content));assert.equal(await readFile(join(outside,'sentinel.txt'),'utf8'),'outside');
  console.log('PASS workspace file, hash, pagination, path guards, fixed command, timeout, revoke');
});
test('G1 read-only mode hides write and process tools',async t=>{
  await mkdir(join(process.cwd(),'.runtime'),{recursive:true});
  const root=await mkdtemp(join(process.cwd(),'.runtime','mvp-readonly-'));
  const m=await makeMvp({root,write:false,exec:false,commands:{},assertActive:async()=>{},audit:async()=>{}});
  const [a,b]=InMemoryTransport.createLinkedPair();const c=new Client({name:'readonly-test',version:'0.1.0'});t.after(async()=>{await c.close();await m.stop();});
  await m.server.connect(a);await c.connect(b);
  const names=(await c.listTools()).tools.map(x=>x.name);assert.equal(names.length,10);assert.ok(!names.includes('write_file'));assert.ok(!names.includes('start_process'));
});
