import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { resolve } from 'node:path';
import { randomUUID,createHash } from 'node:crypto';
import {approveSynthetic,findSyntheticSession} from './helpers/local-approval.ts';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
test('G1 standalone alpha actual stdio process',async t=>{
  const c=new Client({name:'alpha-stdio-test',version:'0.1.0'});
  const transport=new StdioClientTransport({command:process.execPath,args:[resolve('src/mvp-stdio.ts'),'--sandbox-write','--sandbox-exec'],stderr:'ignore'});
  t.after(()=>c.close());await c.connect(transport);
  assert.equal((await c.listTools()).tools.length,26);
  async function call(name:string,args:Record<string,unknown>={}){const r=await c.callTool({name,arguments:args});assert.equal(r.isError??false,false,JSON.stringify(r));return JSON.parse((r.content as Array<{text:string}>)[0].text);}
  assert.equal((await call('get_device_info')).platform,'win32');
  const content=randomUUID(),sha=createHash('sha256').update(content).digest('hex');
  assert.equal((await call('write_file',{path:'proof.txt',content,expectedHash:null})).sha256,sha);
  assert.equal((await call('read_file',{path:'proof.txt'})).text,content);
  const req=await call('start_process',{template:'selftest'});assert.equal(req.status,'awaiting_approval');const base=await findSyntheticSession(req.approvalId);await approveSynthetic(base,req);const p=await call('start_process',{template:'selftest',approvalId:req.approvalId});assert.equal((await c.callTool({name:'start_process',arguments:{template:'selftest',approvalId:req.approvalId}})).isError,true);let out;
  for(let i=0;i<50;i++){out=await call('read_process_output',{id:p.id,channel:'out'});if(out.status!=='running')break;await new Promise(r=>setTimeout(r,40));}
  assert.equal(out.status,'completed');assert.equal(Buffer.from(out.base64,'base64').toString(),'NEXUSBRIDGE_ALPHA_OK');
  const audit=await call('get_audit_log',{limit:100});assert.ok(audit.records.some((r:{action:string})=>r.action==='write_file_ok'));assert.ok(audit.records.some((r:{action:string})=>r.action==='read_process_output'));assert.ok(!JSON.stringify(audit).includes(content));assert.ok(!JSON.stringify(audit).includes('proof.txt'));await writeFile(join(base,'control','stop.flag'),'STOP',{flag:'wx'});assert.equal((await c.callTool({name:'read_file',arguments:{path:'proof.txt'}})).isError,true);
});
