import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,writeFile,rm,access} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {openAuditJournal,readAuditAnchor} from '../src/g1-audit-journal.ts';
test('trusted audit anchor rejects valid-prefix truncation and unanchored restart',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'audit-anchor-')),root=join(base,'audit'),id=randomUUID();await mkdir(root);t.after(()=>rm(base,{recursive:true,force:true}));
  const j=await openAuditJournal(root,id,{requireAnchorOnExisting:true});await j.append({action:'ping'});
  const first=(await j.snapshot()).anchor;await j.append({action:'get_policy'});const full=await j.snapshot();await j.close();
  assert.equal(full.summary.retentionDays,30);assert.equal(full.summary.retentionEligible,false);
  const anchorPath=join(base,'anchor.json');await writeFile(anchorPath,JSON.stringify(full.anchor));
  assert.deepEqual(await readAuditAnchor(anchorPath,id),full.anchor);
  await assert.rejects(openAuditJournal(root,id,{requireAnchorOnExisting:true}),/anchor required/);
  const resumed=await openAuditJournal(root,id,{anchor:first,requireAnchorOnExisting:true});await resumed.append({action:'ping'});await resumed.close();
  const file=join(root,'audit-v1.jsonl'),lines=(await readFile(file,'utf8')).split('\n');await writeFile(file,lines[0]+'\n');
  await assert.rejects(openAuditJournal(root,id,{anchor:full.anchor,requireAnchorOnExisting:true}),/anchor mismatch/);
});
test('retention retirement requires exact archive, elapsed days and current anchor',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'audit-retire-')),root=join(base,'audit'),id=randomUUID();await mkdir(root);t.after(()=>rm(base,{recursive:true,force:true}));
  const j=await openAuditJournal(root,id);await j.append({action:'ping'});await j.close();
  // Synthetic old audit record with valid recomputed chain, never a real log.
  const file=join(root,'audit-v1.jsonl'),r=JSON.parse(await readFile(file,'utf8'));r.utc=new Date(Date.now()-31*86400000).toISOString();
  const {digest:ignored,...body}=r;r.digest=createHash('sha256').update(JSON.stringify(body)).digest('hex');await writeFile(file,JSON.stringify(r)+'\n');
  const anchor={v:1 as const,workspaceId:id,seq:1,digest:r.digest};
  const normal=await openAuditJournal(root,id,{anchor});const snap=await normal.snapshot();assert.equal(snap.summary.retentionEligible,true);
  await assert.rejects(normal.retireArchived(snap.bytes,snap.summary.head),/owner anchor/);await normal.close();
  const archive=join(base,'archive.jsonl');await writeFile(archive,snap.bytes);
  const maintenance=await openAuditJournal(root,id,{anchor,maintenance:true,retentionDays:30});
  await assert.rejects(maintenance.retireArchived(Buffer.from('wrong'),snap.summary.head),/identical archive/);
  await maintenance.retireArchived(await readFile(archive),snap.summary.head);await maintenance.close();
  await assert.rejects(access(file),{code:'ENOENT'});assert.deepEqual(await readFile(archive),snap.bytes);
  await assert.rejects(openAuditJournal(root,id,{anchor,requireAnchorOnExisting:true}),/journal missing/);
});
test('owner audit CLI verifies archive and refuses noninteractive anchor',async t=>{
  const base=await mkdtemp(join(resolve('.runtime'),'audit-cli-')),id=randomUUID();
  t.after(()=>rm(base,{recursive:true,force:true}));
  const roots=Object.fromEntries(['audit','control','workspace','checkpoints','pending','archive'].map(x=>[x,join(base,x)]));
  for(const p of Object.values(roots))await mkdir(p);
  const profile=join(roots.control,'profile.json');
  await writeFile(profile,JSON.stringify({v:1,sessionId:id,auditRoot:roots.audit,controlRoot:roots.control,workspaceRoot:roots.workspace,checkpointRoot:roots.checkpoints,pendingRoot:roots.pending,auditRetentionDays:30}));
  const j=await openAuditJournal(roots.audit,id);await j.append({action:'ping'});const snap=await j.snapshot();await j.close();
  const script=resolve('scripts/audit-local.mts');
  const inspect=spawnSync(process.execPath,[script,'inspect',profile],{encoding:'utf8',timeout:10000});assert.equal(inspect.status,0,inspect.stderr);assert.match(inspect.stdout,/AUDIT_VERIFIED/);
  const rejected=spawnSync(process.execPath,[script,'anchor',profile],{encoding:'utf8',timeout:10000});assert.notEqual(rejected.status,0);await assert.rejects(access(join(roots.control,'audit-anchor.json')),{code:'ENOENT'});
  const archive=spawnSync(process.execPath,[script,'archive',profile,roots.archive],{encoding:'utf8',timeout:10000});assert.equal(archive.status,0,archive.stderr);
  assert.deepEqual(await readFile(join(roots.archive,'audit-'+id+'-'+snap.summary.head+'.jsonl')),snap.bytes);
});
