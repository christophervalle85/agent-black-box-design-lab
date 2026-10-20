/* Test-only generator for a DURABLY reserved and not-yet-acknowledged
 * HMAC audit fixture. Deliberate process exit models controller mid-dispatch;
 * an actual user file, trusted UI or signing key is never involved. */
import {mkdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {AuditStore} from '../src/audit.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createAuditedMacTransferController} from '../src/macos-transfer-controller.mjs';
import {encodeMacKeychainUnsignedReview}
  from '../src/macos-controller-keychain.mjs';
import {FIXED_BYTES} from './mcp-macos-reviewed-contract-vector.mjs';

if(process.argv.length!==3)process.exit(90);
const dir=resolve(process.argv[2]);
mkdirSync(dir,{recursive:true,mode:0o700});
const audit=new AuditStore(join(dir,'handoff-audit.jsonl'),{
  externalReceiptFile:null
});
const now=Date.now();
const controller=createAuditedMacTransferController({
  store:audit,clock:()=>now,syntheticTransport:context=>{
    const proof=audit.verify();
    const unsigned=encodeMacKeychainUnsignedReview(context.transaction,{
      reservationMac:proof.head,now
    });
    writeFileSync(join(dir,'audit-wire.txt'),unsigned,{mode:0o600,flag:'wx'});
    // No terminal result. Audit must end in a durable RESERVED event.
    process.stdout.write('BBX_AUDIT_FIXTURE_RESERVED\n');
    process.exit(0);
  }
});
const intent=createMacTransferIntent({
  operation:'import',noteName:'bbx-test-reviewed.txt',
  bytes:FIXED_BYTES,now
});
const review=controller.host.request(intent);
if(!controller.controller.decide(review.reviewId,'approve'))process.exit(87);
void controller.host.dispatchSynthetic({
  reviewId:review.reviewId,intent,bytes:FIXED_BYTES
});
