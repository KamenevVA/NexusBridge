import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, link, symlink, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { openAuditJournal } from '../src/g1-audit-journal.ts';
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
async function sandbox(t:TestContext) {
  const parent=join(process.cwd(),'.runtime');await mkdir(parent,{recursive:true});
  const base=await mkdtemp(join(parent,'g1-audit-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const root=join(base,'journal');await mkdir(root);return {base,root,file:join(root,'audit-v1.jsonl')};
}
test('G1 audit concurrent append, redaction, pagination and restart',async t=>{
  const {root,file}=await sandbox(t);const id=randomUUID();
  const j=await openAuditJournal(root,id);t.after(()=>j.close());
  await assert.rejects(openAuditJournal(root,id),{code:'EEXIST'});
  const path='synthetic confidential filename.txt',template='synthetic-private-template';
  const events=await Promise.all([
    j.append({action:'write_file_attempt',path,expectedHash:null,sha256:sha('test')}),
    j.append({action:'write_file_ok',path,sha256:sha('test')}),
    j.append({action:'start_process_attempt',template}),
    j.append({action:'start_process_ok',id:randomUUID()})
  ]);
  assert.deepEqual(events.map(x=>x.seq),[1,2,3,4]);assert.equal(events[1].prev,events[0].digest);
  assert.equal(events[0].fields.pathDigest,sha(path));assert.equal(events[2].fields.templateDigest,sha(template));
  const raw=await readFile(file,'utf8');assert.ok(!raw.includes(path));assert.ok(!raw.includes(template));
  assert.throws(()=>j.append({action:'write_file_ok',content:'synthetic-secret'}),/Unsupported audit event/);
  assert.throws(()=>j.append({action:'read_file',sha256:'synthetic-secret'}),/Invalid audit hash/);
  const a=await j.page(0,2);assert.equal(a.nextOffset,2);assert.equal(a.head,events[3].digest);
  const b=await j.page(2,2);assert.equal(b.nextOffset,null);assert.deepEqual(b.records,events.slice(2));
  await j.close();
  const reopened=await openAuditJournal(root,id);t.after(()=>reopened.close());
  assert.deepEqual((await reopened.page()).records,events);
  const next=await reopened.append({action:'policy_revoked',outcome:'ok'});assert.equal(next.seq,5);assert.equal(next.prev,events[3].digest);
  await reopened.close();await assert.rejects(openAuditJournal(root,randomUUID()),/validation/);
});
test('G1 audit detects in-place tampering and incomplete records',async t=>{
  const {root,file}=await sandbox(t),id=randomUUID(),j=await openAuditJournal(root,id);t.after(()=>j.close());
  await j.append({action:'read_file',path:'a.txt',sha256:sha('a')});
  const original=await readFile(file,'utf8');const damaged=original.replace(sha('a'),sha('b'));assert.equal(damaged.length,original.length);
  await writeFile(file,damaged);await assert.rejects(j.page(),/validation failed/);
  await assert.rejects(j.append({action:'ping'}),/unavailable/);await j.close();
  await assert.rejects(openAuditJournal(root,id),/validation failed/);
  await writeFile(file,original.slice(0,-1));await assert.rejects(openAuditJournal(root,id),/Incomplete/);
});
test('G1 audit rejects reparse roots, hardlinks and exhausted capacity',async t=>{
  const {base,root,file}=await sandbox(t);const id=randomUUID(),junction=join(base,'junction');
  await symlink(root,junction,'junction');await assert.rejects(openAuditJournal(junction,id),/Unsafe audit root/);
  const j=await openAuditJournal(root,id,{maxRecords:1});t.after(()=>j.close());
  await j.append({action:'ping'});await assert.rejects(j.append({action:'ping'}),/capacity/);
  await assert.rejects(j.page(),/unavailable/);await j.close();
  await link(file,join(base,'audit-hardlink'));await assert.rejects(openAuditJournal(root,id),/Unsafe audit file/);
});
