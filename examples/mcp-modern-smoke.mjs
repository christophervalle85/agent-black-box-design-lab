// Dependency-free 2026-07-28 MCP client smoke. Uses the published modern wire
// shapes; official SDK interoperability runs separately in GitHub Actions.
import { spawn } from 'node:child_process';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJsonLines, sendJsonLine } from '../src/mcp-wire.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const gateway=spawn(process.execPath,[join(root,'src/mcp-gateway.mjs')],{cwd:root,stdio:['pipe','pipe','inherit']});
const meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'blackbox-modern-smoke',version:'0.5.0'}};
let n=0;const waits=new Map();
readJsonLines(gateway.stdout,{onMessage:msg=>{const wait=waits.get(msg.id);if(!wait)return;clearTimeout(wait.timer);waits.delete(msg.id);wait.resolve(msg);},onError:err=>{for(const wait of waits.values())wait.reject(err);waits.clear();}});
function request(method,params={}){
  const id=++n;return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{waits.delete(id);reject(new Error('MCP modern smoke timed out'));},20000);
    waits.set(id,{timer,resolve,reject});sendJsonLine(gateway.stdin,{jsonrpc:'2.0',id,method,params:{...params,_meta:meta}});
  });
}
try{
  const discover=await request('server/discover');
  if(!discover.result?.supportedVersions?.includes('2026-07-28'))throw Error('Modern discovery failed');
  const list=await request('tools/list');
  if(!list.result || list.result.resultType!=='complete' || list.result.tools.map(t=>t.name).join(',')!=='read_note,write_note')throw Error('Unsafe tool discovery');
  const allow=await request('tools/call',{name:'read_note',arguments:{path:'notes.txt'}});
  const block=await request('tools/call',{name:'read_note',arguments:{path:'.env'}});
  if(allow.result?.isError || !block.result?.isError)throw Error('Unexpected security decision');
  console.log('PASS: Modern 2026-07-28 stdio discovery, tool listing, real downstream read and credential denial.');
}catch(error){console.error('Modern MCP smoke failed:',error.message);process.exitCode=1;}
finally{gateway.stdin.end();gateway.kill('SIGTERM');}
