import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditStore } from './audit.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const file=resolve(process.env.MCP_AUDIT_FILE ?? join(root,'data','audit.jsonl'));
const action=process.argv[2];
if(!['seal','verify'].includes(action)){
  console.error('Usage: npm run audit:verify | npm run audit:seal (one-time explicit legacy seal)');
  process.exitCode=2;
}else {
  try {
    const store=new AuditStore(file,{allowLegacySeal:action==='seal'});
    const verified=store.verify();
    console.log(JSON.stringify({ok:verified.ok,records:verified.records,chainHead:verified.head,auditFile:file,action},null,2));
  }catch(error){console.error('AUDIT INTEGRITY CHECK FAILED:',error.message);process.exitCode=1;}
}
