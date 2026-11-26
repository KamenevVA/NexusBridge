
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,rename,symlink,readFile,writeFile,rm,access} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
test('G1 pinned native parent cannot be replaced with a junction during creation',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'g1-pin-')),parent=join(base,'work'),outside=join(base,'outside'),moved=join(base,'moved');
  await mkdir(parent);await mkdir(outside);await writeFile(join(outside,'sentinel.txt'),'unchanged');
  t.after(()=>rm(base,{recursive:true,force:true}));
  const exe=join(base,'pin-test.exe'),compiler=join(process.env.SystemRoot??'C:\\Windows','Microsoft.NET','Framework64','v4.0.30319','csc.exe');
  const build=spawnSync(compiler,['/nologo','/target:exe','/platform:x64','/define:NB_TEST_PIN_PAUSE','/out:'+exe,resolve('native/FileMove.cs')],{windowsHide:true,encoding:'utf8',timeout:15000});
  assert.equal(build.status,0,build.stdout+build.stderr);
  const bytes=Buffer.from('synthetic pinned write'),hash=createHash('sha256').update(bytes).digest('hex');
  const child=spawn(exe,['io-write',join(parent,'new.txt'),'new',hash,''],{windowsHide:true,stdio:['pipe','pipe','pipe']});
  let stderr='',stdout='';child.stdout.on('data',b=>stdout+=b);
  const done=new Promise<number|null>((ok,fail)=>{child.once('error',fail);child.once('close',ok);});
  t.after(()=>{child.kill()});child.stdin.end(bytes);
  await new Promise<void>((ok,fail)=>{const timer=setTimeout(()=>fail(Error('No pin marker: '+stderr)),5000);child.stderr.on('data',b=>{stderr+=b;if(stderr.includes('SYNTHETIC_PIN_READY')){clearTimeout(timer);ok();}});child.once('close',()=>{clearTimeout(timer);if(!stderr.includes('SYNTHETIC_PIN_READY'))fail(Error(stderr));});});
  let swapped=false;
  try{await rename(parent,moved);swapped=true;await symlink(outside,parent,'junction');}catch(e){if(swapped)throw e;assert.ok(['EPERM','EACCES','EBUSY'].includes((e as NodeJS.ErrnoException).code??''),String(e));}
  const exit=await done;
  assert.equal(swapped,false,'pinned parent must deny rename');
  assert.equal(exit,0,stderr);assert.match(stdout,/WRITE_OK/);
  assert.deepEqual(await readFile(join(parent,'new.txt')),bytes);
  assert.equal(await readFile(join(outside,'sentinel.txt'),'utf8'),'unchanged');
  await assert.rejects(access(join(outside,'new.txt')),{code:'ENOENT'});
});
