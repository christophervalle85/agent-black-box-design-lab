import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditStore } from './audit.mjs';
import { exportReceipt, receiveReceipt, compareReceipt, readLedger } from './checkpoints.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const file=resolve(process.env.MCP_AUDIT_FILE??join(root,'data','audit.jsonl'));
const command=process.argv[2];
const option=(name)=>{
  const pos=process.argv.indexOf(name,3);
  return pos>=0?process.argv[pos+1]:null;
};
try{
  if(command==='export'){
    const store=new AuditStore(file);
    console.log(JSON.stringify(exportReceipt(store)));
  }else if(command==='receive'){
    const ledger=option('--ledger');
    if(!ledger)throw Error('Pass --ledger ABSOLUTE_FILE on the separately controlled receiver.');
    // No server, no automatic syncing of files or credentials. Input comes from a user-reviewed pipe.
    let input='';
    for await(const data of process.stdin){input+=data; if(Buffer.byteLength(input)>4096)throw Error('Receipt exceeds size limit.');}
    console.log(JSON.stringify(receiveReceipt(ledger,JSON.parse(input)),null,2));
  }else if(command==='compare'){
    const receiptPath=option('--receipt');
    if(!receiptPath)throw Error('Pass --receipt FILE obtained from independent storage.');
    const store=new AuditStore(file);
    console.log(JSON.stringify(compareReceipt(store,JSON.parse(readFileSync(receiptPath,'utf8'))),null,2));
  }else if(command==='ledger'){
    const ledger=option('--ledger');
    if(!ledger)throw Error('Pass --ledger ABSOLUTE_FILE.');
    const entries=readLedger(ledger);
    console.log(JSON.stringify({ok:true,records:entries.length,latest:entries.at(-1)??null},null,2));
  }else{
    throw Error('Usage: anchor:export | anchor:receive -- --ledger PATH | anchor:compare -- --receipt FILE | anchor:ledger -- --ledger PATH');
  }
}catch(e){console.error('CHECKPOINT INCIDENT: '+e.message);process.exitCode=1;}
