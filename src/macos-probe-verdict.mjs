/**
 * Explicit verdict for the macOS native probe. This is a test verdict, not
 * a remote attestation or proof that arbitrary Node code is sandboxed.
 */
export function assessMacProbe(result) {
  if(!result || typeof result !== 'object' || Array.isArray(result)) throw Error('Invalid native sandbox probe result.');
  for(const field of ['hostFileDenied','networkDenied','sandboxHomeWriteAllowed']) {
    if(typeof result[field] !== 'boolean') throw Error('Incomplete native sandbox probe: '+field);
  }
  if(!Number.isInteger(result.networkErrorNumber) || typeof result.hostFileError!=='string' || typeof result.sandboxHomeError!=='string')
    throw Error('Malformed native sandbox probe diagnostic fields.');
  // Darwin EPERM=1 and EACCES=13. Unreachable/refused/timed-out network is
  // NOT a kernel denial; nor is ENOENT a genuine host-file read denial.
  const filePermission = /^(?:NSCocoaErrorDomain:257|NSPOSIXErrorDomain:(?:1|13))$/.test(result.hostFileError);
  const networkPermission = [1,13].includes(result.networkErrorNumber);
  const checks = [
    {name:'User-owned host file inaccessible to sandboxed helper',passed:result.hostFileDenied && filePermission},
    {name:'Reachable loopback TCP connection denied by OS',passed:result.networkDenied && networkPermission},
    {name:'Helper can write and clean up inside sandbox home',passed:result.sandboxHomeWriteAllowed && result.sandboxHomeError===''}
  ];
  return {ok:checks.every(x=>x.passed),checks};
}
