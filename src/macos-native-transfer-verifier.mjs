/**
 * v0.8 synthetic native macOS Touch ID review binding, *not production auth*.
 *
 * Only a trusted in-process controller/acceptance harness may obtain the
 * verified native executable and provide an immutable review to this call.
 * The helper is ad-hoc signed for testing; no Developer ID peer trust exists.
 */
import {spawn} from 'node:child_process';
import {homedir,tmpdir} from 'node:os';
import {validateMacTransferIntent} from './macos-transfer-intent.mjs';

const uuid4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function assertReview(context,{now=Date.now()}={}) {
  if(!context || typeof context!=='object' || Array.isArray(context) ||
     Reflect.ownKeys(context).length!==3 ||
     !['reviewId','intent','decision'].every(x=>Object.hasOwn(context,x)) ||
     typeof context.reviewId!=='string' || !uuid4.test(context.reviewId) ||
     context.decision!=='approve')
    throw Error('Invalid trusted Touch ID review context.');
  return {id:context.reviewId,intent:validateMacTransferIntent(context.intent,{now})};
}
export function assessNativeMacTransferTouchId(context,observed,{now=Date.now()}={}) {
  const {id,intent}=assertReview(context,{now});
  if(!observed || observed.error || observed.signal ||
     observed.stderr!=='' || typeof observed.stdout!=='string')
    throw Error('Native Touch ID helper failed or produced unexpected diagnostics.');
  const fields=[id,intent.nonce,intent.sha256,intent.operation,
    intent.noteName,String(intent.byteLength)].join(' ');
  const success='BBX_TRANSFER_TOUCHID_AUTHENTICATED '+fields+'\n';
  const cancelled='BBX_TRANSFER_TOUCHID_USER_CANCELLED '+fields+'\n';
  if(observed.status===0 && observed.stdout===success)return 'authenticated';
  if(observed.status===83 && observed.stdout===cancelled)return 'cancelled';
  throw Error('Native Touch ID did not supply accepted, review-bound OS evidence.');
}
/** Runs ONLY a precompiled/test-signed executable supplied by trusted code. */
export async function evaluateNativeMacTransferTouchId(context,{
  executable,signal=null,timeoutMs=30000,now=Date.now
}={}) {
  if(process.platform!=='darwin')
    throw Error('Real macOS required for native Touch ID.');
  if(typeof executable!=='string' || !executable.startsWith('/') ||
     executable.includes('\0') || typeof now!=='function' ||
     !Number.isSafeInteger(timeoutMs) || timeoutMs<1 || timeoutMs>30000)
    throw Error('Invalid native Touch ID process configuration.');
  const {id,intent}=assertReview(context,{now:now()});
  if(signal?.aborted)throw Error('Touch ID review was cancelled before launch.');
  const args=[id,intent.operation,intent.noteName,String(intent.byteLength),
    intent.sha256,intent.nonce];
  const result=await new Promise(resolve=>{
    const child=spawn(executable,args,{
      shell:false,stdio:['ignore','pipe','pipe'],
      env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
    });
    let stdout='',stderr='',error=null,overflow=false,terminated=false;
    const terminate=()=>{
      terminated=true;
      child.kill('SIGKILL');
    };
    const onAbort=()=>terminate();
    signal?.addEventListener('abort',onAbort,{once:true});
    const timer=setTimeout(terminate,timeoutMs);
    child.on('error',e=>{error=e;});
    child.stdout?.on('data',bytes=>{
      stdout+=bytes.toString('utf8');
      if(stdout.length>512){overflow=true;terminate();}
    });
    child.stderr?.on('data',bytes=>{
      stderr+=bytes.toString('utf8');
      if(stderr.length>512){overflow=true;terminate();}
    });
    child.on('close',(status,processSignal)=>{
      clearTimeout(timer);
      signal?.removeEventListener('abort',onAbort);
      resolve({status,stdout,stderr,error,signal:processSignal,
        terminated,overflow});
    });
    if(signal?.aborted)terminate();
  });
  if(result.terminated || result.overflow || signal?.aborted)
    throw Error('Native Touch ID review cancelled, timed out or exceeded limits.');
  // Recheck expiry *after* completing a potentially slow OS prompt.
  return assessNativeMacTransferTouchId(context,result,{now:now()});
}
