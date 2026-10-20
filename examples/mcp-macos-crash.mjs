/**
 * Show a targeted, bounded summary of the most recent native macOS probe
 * crash without printing raw crash reports, audit files, or credentials.
 * Apple documents the "Termination Reason" and faulting-thread frames as
 * key diagnostics for EXC_BREAKPOINT / SIGTRAP.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

const limited=(value,max=300)=>typeof value==='string'?value.slice(0,max):'';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const compact=value=>{
  if (typeof value==='string') return value.slice(0,500);
  if (object(value) || Array.isArray(value)) return JSON.stringify(value).slice(0,500);
  return null;
};
export function summarizeProbeCrash(source) {
  if(typeof source!=='string' || !source.trim()) throw Error('Empty macOS crash report.');
  let report;
  let header={};
  const firstNewline=source.indexOf('\n');
  try {
    report=JSON.parse(source);
  }catch {
    if(firstNewline<0)report=null;
    else {
      try {
        header=JSON.parse(source.slice(0,firstNewline));
        report=JSON.parse(source.slice(firstNewline+1));
      }catch{report=null;}
    }
  }
  if(object(report)) {
    const idx=Number.isSafeInteger(report.faultingThread)?report.faultingThread:
      report.threads?.findIndex(t=>t.triggered===true);
    const thread=Array.isArray(report.threads)&&idx>=0?report.threads[idx]:null;
    const names=Array.isArray(report.usedImages)?report.usedImages:[];
    const frames=Array.isArray(thread?.frames)?thread.frames.slice(0,10).map(f=>({
      image:typeof names[f.imageIndex]?.name==='string'?names[f.imageIndex].name:'unknown',
      symbol:limited(f.symbol??f.rawSymbol??'(unsymbolicated)',120)
    })):[];
    const info=object(report.asi)?Object.fromEntries(Object.entries(report.asi).slice(0,6).map(([k,v])=>[limited(k,80),compact(v)])):null;
    return {
      format:'ips',process:limited(report.procName??header.app_name??'',80),
      exceptionType:limited(report.exception?.type??'',100),
      exceptionSignal:limited(report.exception?.signal??'',100),
      terminationNamespace:limited(report.termination?.namespace??'',100),
      terminationCode:report.termination?.code??null,
      applicationSpecificInformation:info,
      faultingThread:Number.isSafeInteger(idx)?idx:null,frames
    };
  }
  const get=label=>{
    const found=source.match(new RegExp('^'+label+':\\s*(.+)$','im'));
    return limited(found?.[1]??'',250);
  };
  return {
    format:'crash',
    process:get('Process'),
    exceptionType:get('Exception Type'),
    terminationReason:get('Termination Reason'),
    applicationSpecificInformation:get('Application Specific Information'),
    faultingThread:get('Crashed Thread')||get('Triggered by Thread'),
    frames:source.split('\n').filter(line=>/libsystem_secinit|sandbox_init|_libsecinit|swift_abort|_assertionFailure/i.test(line)).slice(0,8).map(line=>limited(line.trim(),180))
  };
}
function main() {
  if(process.platform!=='darwin')throw Error('Mac crash diagnostics require macOS.');
  const directory=join(homedir(),'Library','Logs','DiagnosticReports');
  if(!existsSync(directory))throw Error('No user diagnostic-report folder. Use Console > Crash Reports instead.');
  const recent=readdirSync(directory)
    .filter(name=>/^blackbox-sandbox-probe(?:[-_].*)?\.(ips|crash)$/i.test(name))
    .map(name=>({name,path:join(directory,name)}))
    .filter(x=>statSync(x.path).isFile()&&statSync(x.path).size<12*1024*1024)
    .map(x=>({...x,time:statSync(x.path).mtimeMs}))
    .filter(x=>Date.now()-x.time<24*60*60*1000)
    .sort((a,b)=>b.time-a.time);
  if(!recent.length) {
    console.log('No recent blackbox-sandbox-probe .ips/.crash file in ~/Library/Logs/DiagnosticReports.');
    console.log('Open Console > Crash Reports and look for blackbox-sandbox-probe.');
    console.log('Apple Console can also filter type:error, subsystem:com.apple.sandbox.reporting, category:violation.');
    return;
  }
  const newest=recent[0];
  console.log('Crash report: '+basename(newest.name));
  console.log('Crash report age (minutes): '+Math.floor((Date.now()-newest.time)/60000));
  console.log(JSON.stringify(summarizeProbeCrash(readFileSync(newest.path,'utf8')),null,2));
  console.log('This is a diagnostic summary, not an OS-isolation success result.');
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href){
  try {main();} catch(e) {console.error('MAC PROBE DIAGNOSTICS FAILED: '+e.message);process.exitCode=1;}
}
