import {mkdir,readFile,writeFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
import {createLocalGuard} from '../../src/g1-local-guard.ts';
export async function syntheticGuard(base:string){
  const controlRoot=join(base,'control'),pendingRoot=join(base,'pending');
  await mkdir(controlRoot);await mkdir(pendingRoot);
  const guard=await createLocalGuard({sessionId:randomUUID(),controlRoot,pendingRoot});
  return {guard,controlRoot,pendingRoot};
}
// Explicit synthetic owner action in the test harness, never available as an MCP tool.
export async function approveSynthetic(base:string,decision:{status:string;approvalId:string;digest:string;expiresAt:number}){
  assert.equal(decision.status,'awaiting_approval');
  const p=JSON.parse(await readFile(join(base,'pending',decision.approvalId+'.json'),'utf8'));
  assert.equal(p.id,decision.approvalId);assert.equal(p.digest,decision.digest);
  await writeFile(join(base,'control',p.id+'.json'),JSON.stringify({v:1,id:p.id,sessionId:p.sessionId,digest:p.digest,expiresAt:p.expiresAt}),{flag:'wx'});
}
export async function findSyntheticSession(id:string){
  const root=resolve('.runtime');
  const candidates:string[]=[];
  for(const entry of await readdir(root,{withFileTypes:true})){
    if(!entry.isDirectory()||!/^alpha-[A-Za-z0-9]+$/.test(entry.name))continue;
    const base=join(root,entry.name);
    try{const p=JSON.parse(await readFile(join(base,'pending',id+'.json'),'utf8'));if(p.id===id)candidates.push(base);}catch{}
  }
  assert.equal(candidates.length,1);return candidates[0];
}
