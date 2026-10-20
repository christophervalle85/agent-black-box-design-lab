/**
 * Explicit in-process test hook, not a configurable production downstream.
 * Experimental launching is never permitted by required-mode or Linux.
 */
export function chooseGatewayLaunch({standard,experimental,mode='off',platform=process.platform}={}) {
  if(!experimental)return standard;
  if(mode!=='off'||platform!=='darwin')
    throw Error('Experimental signed XPC fixture is only permitted in macOS off-mode.');
  if(typeof experimental!=='object'||typeof experimental.command!=='string'||
     !experimental.command.startsWith('/')||!Array.isArray(experimental.args)||
     experimental.args.some(v=>typeof v!=='string')||
     typeof experimental.env!=='object'||experimental.env===null)
    throw Error('Malformed experimental test downstream.');
  return experimental;
}
