// G1 integration harness. Not connected to public HTTPS or the G0 server.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createWorkspace } from './workspace.ts';
import { createProcesses } from './processes.ts';
import type {LocalGuard} from './g1-local-guard.ts';
const result=(v:unknown)=>({content:[{type:'text' as const,text:JSON.stringify(v)}]});
const path=z.string().max(1024);
const id=z.string().uuid();
const limit=z.number().int().min(1).max(200).optional();
const offset=z.number().int().min(0).optional();
export async function makeMvp(options:{root:string;checkpointRoot?:string;write:boolean;exec:boolean;assertActive:()=>Promise<void>;audit:(e:object)=>Promise<void>;auditPage?:(offset:number,limit:number)=>Promise<unknown>;guard?:LocalGuard;appContainerProfile?:string;commands:Parameters<typeof createProcesses>[0]}){
  if(options.exec&&!options.guard)throw Error('Local approval guard required for process execution');
  const assertActive=async()=>{await options.assertActive();await options.guard?.assertActive();};
  const files=await createWorkspace(options.root,{...options,assertActive,allowTransfer:options.write&&!!options.guard&&!!options.checkpointRoot});
  const processes=await createProcesses(options.exec?options.commands:{},assertActive,options.appContainerProfile);
  const server=new McpServer({name:'NexusBridge MVP',version:'0.1.0'});
  const readOnly={readOnlyHint:true,openWorldHint:false};
  const write={readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:false};
  server.registerTool('get_policy',{description:'Report local workspace permissions, no secrets',annotations:readOnly},async()=>{await assertActive();await options.audit({action:'get_policy'});return result({read:true,write:options.write,exec:options.exec,localApprovalRequired:!!options.guard,processIsolation:options.appContainerProfile?'appcontainer-zero-capability':'job-only-synthetic',mode:'isolated-development'});});
  server.registerTool('get_device_info',{description:'Report minimal runtime and device platform information; no hostname, user or network identifiers',annotations:readOnly},async()=>{await assertActive();await options.audit({action:'get_device_info'});return result({platform:process.platform,arch:process.arch,node:process.versions.node});});
  if(options.auditPage){server.registerTool('get_audit_log',{description:'Read paginated redacted local audit records for this sandbox',inputSchema:{offset,limit},annotations:readOnly},async a=>{await assertActive();if((a.offset??0)===0)await options.audit({action:'get_audit_log'});return result(await options.auditPage!(a.offset??0,a.limit??100));});}
  server.registerTool('list_directory',{description:'List safe relative workspace entries with pagination',inputSchema:{path,limit,offset},annotations:readOnly},async a=>result(await files.list(a.path,a.limit,a.offset)));
  server.registerTool('directory_tree',{description:'Bounded directory tree',inputSchema:{path,depth:z.number().int().min(0).max(5).optional()},annotations:readOnly},async a=>result(await files.tree(a.path,a.depth)));
  server.registerTool('read_multiple_files',{description:'Read up to eight bounded UTF-8 files',inputSchema:{paths:z.array(path).min(1).max(8)},annotations:readOnly},async a=>result(await Promise.all(a.paths.map(async p=>({path:p,...await files.read(p,0,8000)})))));
  server.registerTool('read_file',{description:'Read paginated UTF-8 workspace text, maximum 4 MiB per file',inputSchema:{path,offset,length:z.number().int().min(1).max(24000).optional()},annotations:readOnly},async a=>result(await files.read(a.path,a.offset,a.length)));
  server.registerTool('read_binary_file',{description:'Read bounded binary bytes as base64 with byte cursor and whole-file SHA-256',inputSchema:{path,offset,length:z.number().int().min(1).max(24000).optional()},annotations:readOnly},async a=>result(await files.readBinary(a.path,a.offset,a.length)));
  server.registerTool('get_file_info',{description:'Return bounded file metadata and SHA-256',inputSchema:{path},annotations:readOnly},async a=>result(await files.info(a.path)));
  server.registerTool('search_files',{description:'Bounded filename search in approved workspace',inputSchema:{query:z.string().min(1).max(256)},annotations:readOnly},async a=>result(await files.search(a.query)));
  server.registerTool('search_content',{description:'Bounded UTF-8 text search in approved workspace',inputSchema:{query:z.string().min(1).max(256)},annotations:readOnly},async a=>result(await files.search(a.query,true)));
  if(options.write){
    server.registerTool('create_directory',{description:'Create one new relative directory; parent must exist',inputSchema:{path},annotations:write},async a=>result(await files.createDirectory(a.path)));
    server.registerTool('write_file',{description:'Create or replace UTF-8 file; existing files require exact SHA-256 and private checkpoint store.',inputSchema:{path,content:z.string().max(4*1024*1024),expectedHash:z.string().regex(/^[0-9a-f]{64}$/).nullable()},annotations:write},async a=>result(await files.write(a.path,a.content,a.expectedHash)));
    server.registerTool('edit_file',{description:'Replace one exact text occurrence, with expected file hash and checkpoint',inputSchema:{path,oldText:z.string().min(1).max(24000),newText:z.string().max(24000),expectedHash:z.string().regex(/^[0-9a-f]{64}$/)},annotations:write},async a=>result(await files.edit(a.path,a.oldText,a.newText,a.expectedHash)));
    server.registerTool('write_binary_file',{description:'Create or replace bounded binary file from canonical base64; existing file requires exact SHA-256 and private checkpoint',inputSchema:{path,base64:z.string().max(Math.ceil(4*1024*1024/3)*4),expectedHash:z.string().regex(/^[0-9a-f]{64}$/).nullable()},annotations:write},async a=>result(await files.writeBinary(a.path,a.base64,a.expectedHash)));
    server.registerTool('apply_patch',{description:'Apply up to 32 ordered unique exact-text edits to one UTF-8 file; all validate before one hash-checked replacement',inputSchema:{path,edits:z.array(z.object({oldText:z.string().min(1).max(24000),newText:z.string().max(24000)})).min(1).max(32),expectedHash:z.string().regex(/^[0-9a-f]{64}$/)},annotations:write},async a=>result(await files.applyPatch(a.path,a.edits,a.expectedHash)));
    server.registerTool('copy_file',{description:'Copy bounded file to new path only',inputSchema:{source:path,destination:path},annotations:write},async a=>result(await files.copy(a.source,a.destination)));
  }
  async function authorize(action:string,details:Record<string,unknown>,approvalId?:string){
    if(!options.guard)throw Error('Local approval guard required');
    const decision=await options.guard.check(action,details,approvalId);
    await options.audit({action:decision.status==='approved'?'approval_consumed':'approval_requested',id:decision.approvalId,sha256:decision.digest});
    await assertActive();
    return decision;
  }
  if(options.write&&options.guard&&options.checkpointRoot){
    const expectedHash=z.string().regex(/^[0-9a-f]{64}$/);
    server.registerTool('move_file',{description:'Move one bounded same-volume file, no overwrite, with checkpoint and exact local approval',inputSchema:{source:path,destination:path,expectedHash,approvalId:id.optional()},annotations:{...write,destructiveHint:true}},async a=>{const approval=await authorize('move_file',{source:a.source,destination:a.destination,expectedHash:a.expectedHash},a.approvalId);if(approval.status!=='approved')return result(approval);return result(await files.move(a.source,a.destination,a.expectedHash));});
    server.registerTool('trash_file',{description:'Move one bounded file to protected recoverable trash; exact local approval, no permanent deletion',inputSchema:{path,expectedHash,approvalId:id.optional()},annotations:{...write,destructiveHint:true}},async a=>{const approval=await authorize('trash_file',{path:a.path,expectedHash:a.expectedHash},a.approvalId);if(approval.status!=='approved')return result(approval);return result(await files.trash(a.path,a.expectedHash));});
    server.registerTool('get_checkpoint_info',{description:'Inspect managed checkpoint and current hashes without reading backup contents',inputSchema:{checkpointId:id},annotations:readOnly},async a=>result(await files.checkpointInfo(a.checkpointId)));
    server.registerTool('restore_file',{description:'Restore a managed checkpoint only, refuse conflicts, exact local approval',inputSchema:{checkpointId:id,expectedHash:expectedHash.nullable(),approvalId:id.optional()},annotations:{...write,destructiveHint:true}},async a=>{const details=await files.describeRestore(a.checkpointId);const approval=await authorize('restore_file',{...details,expectedHash:a.expectedHash},a.approvalId);if(approval.status!=='approved')return result(approval);return result(await files.restore(a.checkpointId,a.expectedHash,details.manifestHash));});
  }
  if(options.exec){
    server.registerTool('start_process',{description:'Start a locally pre-approved fixed executable and argument template, no shell',inputSchema:{template:z.string().max(64),approvalId:id.optional()},annotations:write},async a=>{await assertActive();const approval=await authorize('start_process',processes.describe(a.template),a.approvalId);if(approval.status!=='approved')return result(approval);await options.audit({action:'start_process_attempt',template:a.template,utc:new Date().toISOString()});const r=await processes.start(a.template);try{await options.audit({action:'start_process_ok',id:r.id,utc:new Date().toISOString()});}catch(e){processes.stopAll();throw e;}return result(r);});
    server.registerTool('read_process_output',{description:'Read bounded output bytes in base64 with cursor, stdout or stderr',inputSchema:{id,channel:z.enum(['out','err']),offset,length:z.number().int().min(1).max(24000).optional()},annotations:readOnly},async a=>{const r=await processes.output(a.id,a.channel,a.offset,a.length);await options.audit({action:'read_process_output',id:a.id});return result(r);});
    server.registerTool('send_process_input',{description:'Send bounded UTF-8 input to a locally input-enabled fixed process; no shell or arbitrary command',inputSchema:{id,text:z.string().max(4096),close:z.boolean().optional()},annotations:write},async a=>{await assertActive();await options.audit({action:'send_process_input_attempt',id:a.id});const r=await processes.input(a.id,a.text,a.close);await options.audit({action:'send_process_input_ok',id:a.id});return result(r);});
    server.registerTool('list_sessions',{description:'List only managed process sessions',annotations:readOnly},async()=>{const r=await processes.list();await options.audit({action:'list_sessions'});return result(r);});
    server.registerTool('terminate_process',{description:'Stop a managed process, not arbitrary system PID',inputSchema:{id},annotations:{...write,destructiveHint:true}},async a=>{await options.audit({action:'terminate_process_attempt',id:a.id,utc:new Date().toISOString()});const r=await processes.cancel(a.id);await options.audit({action:'terminate_process_ok',id:a.id});return result(r);});
  }
  return {server,stop:async()=>{options.guard?.stop();processes.dispose();await server.close();}};
}
