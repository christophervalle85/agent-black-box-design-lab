import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {frameBridgeRequest,parseBridgeReply,parseBridgeReplies} from '../src/macos-xpc-bridge-wire.mjs';

const name='bbx-test-hello_7.txt';
test('native bridge frames preserve bounded content and exact byte length',()=>{
 const frame=frameBridgeRequest('WRITE',name,'hello\nworld');
 assert.equal(frame.toString(),'WRITE '+name+' 11\nhello\nworld');
 assert.equal(frameBridgeRequest('READ',name).toString(),'READ '+name+' 0\n');
 assert.equal(frameBridgeRequest('REMOVE',name).toString(),'REMOVE '+name+' 0\n');
});
test('native bridge restricts operations to synthetic names, small ASCII content',()=>{
 for(const path of ['.env','../../.ssh/id_ed25519','/etc/passwd','bbx-test-x.pem','bbx-test-.txt',
   'bbx-test-'+('a'.repeat(52))+'.txt'])assert.throws(()=>frameBridgeRequest('READ',path));
 for(const method of ['SHELL','EXEC','LIST','cleanup_test_note'])
   assert.throws(()=>frameBridgeRequest(method,name));
 for(const data of ['', 'x'.repeat(2001),'secr\u00e9t','test\0escape','hi\rworld'])
   assert.throws(()=>frameBridgeRequest('WRITE',name,data));
 assert.throws(()=>frameBridgeRequest('READ',name,'secret'));
});
test('native bridge rejects truncated and unsolicited response payloads',()=>{
 assert.deepEqual(parseBridgeReply(Buffer.from('OK 3\nhey')),{ok:true,content:'hey'});
 assert.deepEqual(parseBridgeReply(Buffer.from('ERR 0\n')),{ok:false,content:''});
 for(const wire of ['ERR 5\nhello','OK 5\nshorter','OK 4\nhi',
   'OK -1\n','OK 2001\n','OK 1\nab','OK 0001\na','ok 0\n','OK 0'])
   assert.throws(()=>parseBridgeReply(Buffer.from(wire)));
});
test('native bridge parses exactly expected number of binary responses',()=>{
 const p=Buffer.from('OK 3\nheyERR 0\nOK 0\n');
 assert.deepEqual(parseBridgeReplies(p,3),[
   {ok:true,content:'hey'},{ok:false,content:''},{ok:true,content:''}]);
 assert.throws(()=>parseBridgeReplies(p,2));
 assert.throws(()=>parseBridgeReplies(Buffer.from('OK 3\nhe'),1));
});
test('native bridge compiles a bounded C protocol host without shell execution',()=>{
 const native=readFileSync(new URL('../native/macos/xpc/NotesBridgeHost.c',import.meta.url),'utf8');
 assert.match(native,/xpc_connection_send_message_with_reply_sync/);
 assert.match(native,/test_name\(const char \*name\)/);
 assert.match(native,/strcmp\(op,"WRITE"\)/);
 assert.match(native,/strcmp\(op,"READ"\)/);
 assert.match(native,/strcmp\(op,"REMOVE"\)/);
 assert.doesNotMatch(native,/\b(?:system|popen|execvp|execlp)\s*\(/);
});
