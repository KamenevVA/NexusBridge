import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,link,symlink,rm,access,unlink,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
const sha=(b:string|Buffer)=>createHash('sha256').update(b).digest('hex');
const helper=resolve('.runtime/native/NexusBridge.FileMove.exe');
function native(args:string[],input?:Buffer){return spawnSync(helper,args,{input,windowsHide:true,shell:false,timeout:10000,maxBuffer:5*1024*1024});}
function ok(args:string[],input?:Buffer){const r=native(args,input);assert.equal(r.status,0,r.stderr?.toString());return r.stdout;}
test('native read/list/create/write/trash with pinned handles and verified protected backup',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'native-io-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const root=join(base,'root'),store=join(base,'store'),outside=join(base,'outside');
  await mkdir(root);await mkdir(store);await mkdir(outside);
  const dir=join(root,'Кириллица'),file=join(dir,'данные.bin'),backup=join(store,'backup.bak');
  const first=Buffer.from([0,255,1,128,10]),second=Buffer.from('Привет\r\n');
  assert.match(ok(['io-mkdir',dir]).toString(),/MKDIR_OK/);
  assert.match(ok(['io-write',file,'new',sha(first),''],first).toString(),/WRITE_OK/);
  assert.deepEqual(ok(['io-read',file]),first);
  assert.match(ok(['io-stat',file]).toString(),/F\t5/);
  const list=ok(['io-list',root]).toString();assert.ok(list.includes(Buffer.from('Кириллица').toString('base64')+'\tD'));
  assert.notEqual(native(['io-write',file,'new',sha(second),''],second).status,0);
  assert.deepEqual(await readFile(file),first);
  await writeFile(backup,'wrong');
  assert.notEqual(native(['io-write',file,sha(first),sha(second),backup],second).status,0);
  assert.deepEqual(await readFile(file),first);
  await writeFile(backup,first);
  assert.notEqual(native(['io-write',file,sha(first),sha('bad'),backup],second).status,0);
  assert.deepEqual(await readFile(file),first);
  assert.match(ok(['io-write',file,sha(first),sha(second),backup],second).toString(),/WRITE_OK/);
  assert.deepEqual(await readFile(file),second);assert.deepEqual(await readFile(backup),first);
  assert.ok(!(await readdir(dir)).some(n=>n.startsWith('.nb-tmp-')));
  const sentinel=join(outside,'sentinel.txt');await writeFile(sentinel,'outside');
  const junction=join(root,'junction');await symlink(outside,junction,'junction');
  const hard=join(root,'hard.txt');await link(sentinel,hard);
  for(const path of [join(junction,'sentinel.txt'),hard])assert.notEqual(native(['io-read',path]).status,0);
  assert.notEqual(native(['io-list',junction]).status,0);
  assert.notEqual(native(['io-mkdir',join(junction,'escape')]).status,0);
  assert.notEqual(native(['io-write',join(junction,'escape.txt'),'new',sha(first),''],first).status,0);
  await writeFile(file+':synthetic','stream');
  assert.notEqual(native(['io-read',file]).status,0);assert.notEqual(native(['io-stat',file]).status,0);
  assert.notEqual(native(['io-trash',file,sha(second),backup]).status,0);await unlink(file+':synthetic');
  const trash=join(store,'recovery.trash');await writeFile(trash,second);
  assert.match(ok(['io-trash',file,sha(second),trash]).toString(),/TRASH_OK/);
  await assert.rejects(access(file),{code:'ENOENT'});assert.deepEqual(await readFile(trash),second);
  assert.match(ok(['io-write',file,'new',sha(second),''],second).toString(),/WRITE_OK/);
  assert.deepEqual(await readFile(file),second);assert.equal(await readFile(sentinel,'utf8'),'outside');
});

test('native I/O accepts 4 MiB and denies a larger file without changing it',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'native-large-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const file=join(base,'large.bin'),oversize=join(base,'oversize.bin'),bytes=Buffer.alloc(4*1024*1024,0xa5),extra=Buffer.concat([bytes,Buffer.from([1])]);
  assert.match(ok(['io-write',file,'new',sha(bytes),''],bytes).toString(),/WRITE_OK/);
  assert.equal(sha(ok(['io-read',file])),sha(bytes));
  assert.notEqual(native(['io-write',oversize,'new',sha(extra),''],extra).status,0);
  await assert.rejects(access(oversize),{code:'ENOENT'});
  await writeFile(oversize,extra);assert.notEqual(native(['io-read',oversize]).status,0);assert.equal(sha(await readFile(oversize)),sha(extra));
});
