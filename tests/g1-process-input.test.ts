import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {makeMvp} from '../src/mvp-core.ts';
import {syntheticGuard,approveSynthetic} from './helpers/local-approval.ts';
test('G1 MCP bounded process input and output via native Job Object',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'job-mcp-')),root=join(base,'work');
  await mkdir(root);
  const {guard}=await syntheticGuard(base);const logs:object[]=[];let active=true;
  const m=await makeMvp({root,guard,write:false,exec:true,assertActive:async()=>{if(!active)throw Error('Revoked');},audit:async e=>{logs.push(e);},commands:{
    echo:{exe:process.execPath,args:['-e','let s="";process.stdin.on("data",b=>s+=b);process.stdin.on("end",()=>process.stdout.write(s));'],cwd:root,timeoutMs:5000,input:true},
    noinput:{exe:process.execPath,args:['-e','setTimeout(()=>{},5000)'],cwd:root,timeoutMs:5000}
  }});
  const [a,b]=InMemoryTransport.createLinkedPair(),c=new Client({name:'job-mcp-test',version:'0.1.0'});
  t.after(async()=>{await c.close();await m.stop();await rm(base,{recursive:true,force:true});});
  await m.server.connect(a);await c.connect(b);
  const raw=(name:string,args:Record<string,unknown>)=>c.callTool({name,arguments:args});
  async function call(name:string,args:Record<string,unknown>){let r=await raw(name,args);assert.equal(r.isError??false,false,JSON.stringify(r));let v=JSON.parse((r.content as Array<{text:string}>)[0].text);if(name==='start_process'&&v.status==='awaiting_approval'){await approveSynthetic(base,v);r=await raw(name,{...args,approvalId:v.approvalId});assert.equal(r.isError??false,false,JSON.stringify(r));v=JSON.parse((r.content as Array<{text:string}>)[0].text);}return v;}
  const s=await call('start_process',{template:'echo'});
  assert.equal((await raw('send_process_input',{id:s.id,text:'я'.repeat(3000)})).isError,true);
  const text='synthetic input';
  assert.equal((await call('send_process_input',{id:s.id,text})).acceptedBytes,Buffer.byteLength(text));
  assert.equal((await call('send_process_input',{id:s.id,text:'',close:true})).inputClosed,true);
  let out;for(let i=0;i<80;i++){out=await call('read_process_output',{id:s.id,channel:'out'});if(out.status!=='running')break;await new Promise(r=>setTimeout(r,40));}
  assert.equal(out.status,'completed');assert.equal(out.exitCode,0);assert.equal(Buffer.from(out.base64,'base64').toString(),text);
  assert.equal((await raw('send_process_input',{id:s.id,text:'again'})).isError,true);
  const n=await call('start_process',{template:'noinput'});
  assert.equal((await raw('send_process_input',{id:n.id,text:'denied'})).isError,true);
  active=false;
  await new Promise(r=>setTimeout(r,400));assert.equal((await raw('list_sessions',{})).isError,true);
  assert.ok(logs.some(e=>JSON.stringify(e).includes('send_process_input_ok')));
  assert.ok(!JSON.stringify(logs).includes(text));
});
