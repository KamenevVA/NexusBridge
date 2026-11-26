// Standalone alpha sandbox stdio runner. No network, no arbitrary workspace or shell.
import { mkdir,mkdtemp,lstat,realpath } from 'node:fs/promises';
import { join,resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { makeMvp } from './mvp-core.ts';
import { randomUUID } from 'node:crypto';
import { openAuditJournal } from './g1-audit-journal.ts';
const flags=process.argv.slice(2);
if(flags.some(x=>!['--sandbox-write','--sandbox-exec'].includes(x)))throw Error('Only explicit sandbox flags supported');
const base=fileURLToPath(new URL('../.runtime/',import.meta.url));
await mkdir(base,{recursive:true});
const canonical=resolve(base),st=await lstat(canonical);
if(!st.isDirectory()||st.isSymbolicLink()||resolve(await realpath(canonical))!==canonical)throw Error('Unsafe alpha runtime root');
const session=await mkdtemp(join(canonical,'alpha-')),root=join(session,'workspace'),checkpoints=join(session,'checkpoints');
await mkdir(root);await mkdir(checkpoints);
const auditRoot=join(session,'audit');await mkdir(auditRoot);const journal=await openAuditJournal(auditRoot,randomUUID());
let enabled=true;
const assertActive=async()=>{if(!enabled)throw Error('Session stopped');const s=await lstat(canonical);if(s.ino!==st.ino||s.dev!==st.dev||s.isSymbolicLink()||resolve(await realpath(canonical))!==canonical)throw Error('Runtime changed');};
const m=await makeMvp({root,checkpointRoot:checkpoints,write:flags.includes('--sandbox-write'),exec:flags.includes('--sandbox-exec'),assertActive,audit:async e=>{await assertActive();try{await journal.append(e);}catch(e){enabled=false;throw e;}},auditPage:async (offset,limit)=>{await assertActive();try{return await journal.page(offset,limit);}catch(e){enabled=false;throw e;}},commands:{selftest:{exe:process.execPath,args:['-e','process.stdout.write("NEXUSBRIDGE_ALPHA_OK")'],cwd:root,timeoutMs:5000}}});
const transport=new StdioServerTransport();
let closing=false;
async function stop(){if(closing)return;closing=true;enabled=false;await m.stop().catch(()=>{});await journal.close().catch(()=>{});}
await m.server.connect(transport);
process.stdin.once('end',()=>void stop());process.once('SIGINT',()=>void stop());process.once('SIGTERM',()=>void stop());
console.error('NexusBridge alpha isolated sandbox ready');
