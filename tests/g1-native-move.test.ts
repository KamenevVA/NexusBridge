import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,link,symlink,rm,access,unlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
const sha=(b:string|Buffer)=>createHash('sha256').update(b).digest('hex');
const helper=resolve('.runtime/native/NexusBridge.FileMove.exe');
function native(source:string,destination:string,hash:string){
  return spawnSync(helper,[source,destination,hash],{shell:false,windowsHide:true,encoding:'utf8',timeout:5000});
}
test('native move: same-volume verified handle, no clobber, links and ADS denied',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'native-move-test-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const root=join(base,'root'),other=join(base,'other');await mkdir(root);await mkdir(other);
  const a=join(root,'a.txt'),b=join(root,'b.txt'),c=join(other,'c.txt');
  await writeFile(a,'original');await writeFile(b,'existing');
  assert.notEqual(native(a,b,sha('original')).status,0);
  assert.equal(await readFile(a,'utf8'),'original');assert.equal(await readFile(b,'utf8'),'existing');
  assert.notEqual(native(a,c,sha('wrong')).status,0);await assert.rejects(access(c),{code:'ENOENT'});
  await link(a,join(root,'hard.txt'));assert.notEqual(native(a,c,sha('original')).status,0);await unlink(join(root,'hard.txt'));
  await writeFile(a+':synthetic','stream');
  assert.notEqual(native(a,c,sha('original')).status,0);await unlink(a+':synthetic');
  const junction=join(root,'junction');await symlink(other,junction,'junction');
  assert.notEqual(native(a,join(junction,'escape.txt'),sha('original')).status,0);
  await assert.rejects(access(join(other,'escape.txt')),{code:'ENOENT'});
  const r=native(a,c,sha('original'));assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/MOVE_OK/);
  assert.equal(await readFile(c,'utf8'),'original');await assert.rejects(access(a),{code:'ENOENT'});
  const reverse=native(c,a,sha('original'));assert.equal(reverse.status,0,reverse.stderr);assert.equal(await readFile(a,'utf8'),'original');
});
