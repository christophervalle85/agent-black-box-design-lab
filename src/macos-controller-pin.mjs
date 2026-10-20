/**
 * Separate, explicit TEST controller trust enrollment. The public-key
 * fingerprint lives in a private local configuration directory OUTSIDE
 * the repo and OUTSIDE the Keychain; it is never silently re-enrolled.
 * The sandboxed XPC worker has no access to it.
 *
 * A same-user attacker controlling both the Keychain and this local
 * mutable pin could defeat this test anchor. This is not independent
 * production trust provisioning or enterprise managed configuration.
 */
import {
  constants,openSync,closeSync,readFileSync,writeSync,fsyncSync,
  mkdirSync,lstatSync,fstatSync
} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';

const HASH=/^[0-9a-f]{64}$/;
export function macControllerPinPath(home=homedir()){
  return join(home,'Library','Application Support','AgentBlackBox',
              'ControllerTrust','test-controller-rsa.sha256');
}
function assertOwner(st,type,mode){
  if(!st||typeof process.getuid!=='function'||st.uid!==process.getuid()||
     st.nlink!== (type==='dir'?2:1) ||
     !(type==='dir'?st.isDirectory():st.isFile()) ||
     (st.mode&0o777)!==mode)
    throw Error('Untrusted test controller pin filesystem owner or permissions.');
}
function trustDirectory(path){
  const parts=path.split('/');
  const directory=parts.slice(0,-1).join('/');
  const info=lstatSync(directory);
  // An APFS directory can have variable link counts (2 or more); validate
  // owner, mode and no symlink rather than assuming a POSIX nlink count.
  if(info.isSymbolicLink()||!info.isDirectory()||
     info.uid!==process.getuid()||(info.mode&0o777)!==0o700)
    throw Error('Untrusted test controller trust directory.');
  return directory;
}
export function enrollMacControllerPublicPin(sha256,{
  file=macControllerPinPath()
}={}){
  if(typeof sha256!=='string'||!HASH.test(sha256))
    throw Error('Validated RSA controller fingerprint required.');
  const dir=join(file,'..'); // path normalization handled by fs
  mkdirSync(dir,{recursive:true,mode:0o700});
  const parent=trustDirectory(file);
  let descriptor;
  try{
    descriptor=openSync(file,
      constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,
      0o600);
    const bytes=Buffer.from(sha256+'\n','ascii');
    if(writeSync(descriptor,bytes,0,bytes.length)!==bytes.length)
      throw Error('Incomplete test controller pin enrollment.');
    fsyncSync(descriptor);
  }finally{
    if(descriptor!==undefined)closeSync(descriptor);
  }
  const dirfd=openSync(parent,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try{fsyncSync(dirfd);}
  finally{closeSync(dirfd);}
  return true;
}
export function assertMacControllerEnrolledPin(sha256,{
  file=macControllerPinPath()
}={}){
  if(typeof sha256!=='string'||!HASH.test(sha256))
    throw Error('Validated RSA controller fingerprint required.');
  trustDirectory(file);
  const fd=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  let bytes;
  try{
    const st=fstatSync(fd);
    assertOwner(st,'file',0o600);
    if(st.size!==65)
      throw Error('Malformed persistent controller fingerprint.');
    bytes=readFileSync(fd,'ascii');
  }finally{closeSync(fd);}
  if(bytes!==sha256+'\n')
    throw Error('Provisioned controller identity changed: explicit re-enrollment required.');
  return true;
}
