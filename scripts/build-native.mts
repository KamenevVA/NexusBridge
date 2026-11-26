// Build only local native helpers, using the installed Windows .NET Framework compiler.
import {spawnSync} from 'node:child_process';
import {mkdirSync,lstatSync,realpathSync,renameSync,unlinkSync,readFileSync} from 'node:fs';
import {createHash,randomUUID} from 'node:crypto';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
if(process.platform!=='win32'||process.arch!=='x64')throw Error('Windows x64 required');
const root=resolve(fileURLToPath(new URL('../',import.meta.url)));
const base=join(root,'.runtime'),out=join(base,'native');
for(const p of [base,out]){mkdirSync(p,{recursive:true});const s=lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||resolve(realpathSync(p))!==p)throw Error('Unsafe native build directory');}
const compiler=join(process.env.SystemRoot??'C:\\Windows','Microsoft.NET','Framework64','v4.0.30319','csc.exe');
for(const [source,name] of [['JobRunner.cs','NexusBridge.Job.exe'],['FileMove.cs','NexusBridge.FileMove.exe'],['AppContainerJobRunner.cs','NexusBridge.AppContainer.exe']]){
  const target=join(out,name),temp=join(out,'build-'+randomUUID()+'.exe');
  try{
    const c=spawnSync(compiler,['/nologo','/target:exe','/platform:x64','/optimize+','/out:'+temp,join(root,'native',source)],{shell:false,stdio:'inherit',windowsHide:true});
    if(c.error||c.status!==0)throw Error('Native compilation failed: '+source);
    const st=lstatSync(temp);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)throw Error('Unsafe compiled helper');
    try{const prior=lstatSync(target);if(!prior.isFile()||prior.isSymbolicLink()||prior.nlink!==1)throw Error('Unsafe existing helper');}catch(e){if(e.code!=='ENOENT')throw e;}
    renameSync(temp,target);
    console.log(name+' SHA256='+createHash('sha256').update(readFileSync(target)).digest('hex'));
  }finally{try{unlinkSync(temp)}catch{}}
}
