/*
 * TEST-ONLY v0.8: explicitly provisioned, persistent macOS Keychain RSA
 * controller identity. No private-key PEM, passphrase, or private bytes are
 * returned to Node or placed in the native signed host.
 *
 * This is a software Keychain credential, NOT a Secure Enclave RSA key or a
 * production controller authorization service. A same-user process that can
 * invoke this diagnostic helper may request signatures. A separate trusted
 * consent authority and independent pin deployment are still required.
 *
 * "provision" refuses to replace an existing key. "public" and "sign"
 * NEVER provision one. Sign accepts ONLY an exact fixed synthetic import
 * review plus a bounded audit checkpoint, not arbitrary caller bytes.
 * Signing requires a fresh OS biometric consent decision IN THIS separately
 * signed helper after parsing exact transaction fields and before using the
 * Keychain key. Caller cannot supply "approved" or skip this decision.
 * Still not an independent privileged controller or ACL-bound trust root.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "ReviewedTransactionHandoff.h"
#include "ControllerSigningReservation.h"
#include "ControllerAuditVerifier.h"

static NSString *const kKeyTag=@"dev.agentblackbox.test.controller.rsa-pss-v1";
static NSData *tagData(void){
    return [kKeyTag dataUsingEncoding:NSUTF8StringEncoding];
}
static SecKeyRef findPrivateKey(OSStatus *result){
    NSDictionary *lookup=@{
        (id)kSecClass:(id)kSecClassKey,
        (id)kSecAttrApplicationTag:tagData(),
        (id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass:(id)kSecAttrKeyClassPrivate,
        (id)kSecReturnRef:@YES,
        (id)kSecMatchLimit:(id)kSecMatchLimitOne
    };
    SecKeyRef key=NULL;
    const OSStatus status=SecItemCopyMatching((CFDictionaryRef)lookup,
                                               (CFTypeRef *)&key);
    if(result)*result=status;
    return status==errSecSuccess?key:NULL;
}
static bool validRsa2048(SecKeyRef key){
    if(!key)return false;
    CFDictionaryRef attrs=SecKeyCopyAttributes(key);
    if(!attrs)return false;
    NSDictionary *data=(NSDictionary *)attrs;
    const bool valid=[data[(id)kSecAttrKeyType] isEqual:(id)kSecAttrKeyTypeRSA] &&
        [data[(id)kSecAttrKeySizeInBits] integerValue]==2048;
    CFRelease(attrs);
    return valid;
}
static int provision(void){
    OSStatus found=errSecSuccess;
    SecKeyRef existing=findPrivateKey(&found);
    if(existing){CFRelease(existing);return 86;} // never overwrite
    if(found!=errSecItemNotFound)return 87;
    NSDictionary *privateAttrs=@{
        (id)kSecAttrIsPermanent:@YES,
        (id)kSecAttrApplicationTag:tagData(),
        (id)kSecAttrIsSensitive:@YES,
        (id)kSecAttrIsExtractable:@NO
    };
    NSDictionary *attrs=@{
        (id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeySizeInBits:@2048,
        (id)kSecPrivateKeyAttrs:privateAttrs
    };
    CFErrorRef error=NULL;
    SecKeyRef key=SecKeyCreateRandomKey((CFDictionaryRef)attrs,&error);
    if(error)CFRelease(error);
    if(!key)return 87;
    const bool valid=validRsa2048(key);
    CFRelease(key);
    if(!valid)return 87;
    puts("BBX_KEYCHAIN_CONTROLLER_PROVISIONED");
    return 0;
}
static int exportPublic(void){
    OSStatus found=errSecSuccess;
    SecKeyRef privateKey=findPrivateKey(&found);
    if(!privateKey)return 87; // No automatic regeneration.
    if(!validRsa2048(privateKey)){CFRelease(privateKey);return 87;}
    SecKeyRef publicKey=SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);
    if(!publicKey)return 87;
    CFErrorRef error=NULL;
    CFDataRef der=SecKeyCopyExternalRepresentation(publicKey,&error);
    CFRelease(publicKey);
    if(error)CFRelease(error);
    if(!der)return 87;
    NSData *bytes=(NSData *)der;
    const bool valid=[bytes length]>=200&&[bytes length]<=512;
    NSString *encoded=valid?[bytes base64EncodedStringWithOptions:0]:nil;
    if(valid&&encoded)
        printf("BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=%s\n",
               [encoded UTF8String]);
    CFRelease(der);
    return valid&&encoded?0:87;
}
/* Test-only, fresh operator approval occurs in the native Keychain signer,
 * separately from the native receipt host's own Touch ID prompt. No caller
 * supplied approval bit, cached LA context, fallback password or bypass. */
static bool approveExactlyReviewedSyntheticTransaction(
    const BBXPreissuedReview *review){
    if(!review)return false;
    LAContext *context=[[LAContext alloc] init];
    if(!context)return false;
    context.touchIDAuthenticationAllowableReuseDuration=0;
    NSError *error=nil;
    const BOOL available=[context canEvaluatePolicy:
        LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    if(!available){
        [context invalidate];
        [context release];
        return false;
    }
    NSString *reason=[NSString stringWithFormat:
        @"Agent Black Box TEST controller: approve import of "
         @"bbx-test-reviewed.txt (%llu bytes), SHA-256 %.16s..., "
         @"transaction %.12s... Only synthetic data.",
        (unsigned long long)review->byteLength,
        review->sha256,review->transactionId];
    dispatch_semaphore_t completed=dispatch_semaphore_create(0);
    __block BOOL approved=NO;
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:reason
                      reply:^(BOOL success,NSError *failure){
        approved=success&&failure==nil;
        dispatch_semaphore_signal(completed);
    }];
    const long timeout=dispatch_semaphore_wait(completed,
        dispatch_time(DISPATCH_TIME_NOW,40LL*NSEC_PER_SEC));
    [context invalidate];
    [context release];
    /* The callback may still arrive after timeout; keep the diagnostic
       semaphore valid until this short-lived helper process exits. */
    return timeout==0&&approved;
}

static int signFixedSyntheticReview(const char *auditDirectory){
    /* A bounded stdin record has the exact canonical fields and a single
       trailing reservationMac=64-lowercase-hex line; no other fields. */
    char source[900]={0};
    size_t used=0;
    for(;;){
        const int c=fgetc(stdin);
        if(c==EOF)break;
        if(used>=sizeof(source)-1||
           (c!='\n'&&(c<0x20||c>0x7e)))return 87;
        source[used++]=(char)c;
    }
    if(ferror(stdin)||!used)return 87;
    source[used]='\0';
    char *reservation=strstr(source,"reservationMac=");
    if(!reservation||reservation==source)return 87;
    const size_t canonicalLength=(size_t)(reservation-source);
    const size_t resLength=sizeof("reservationMac=")-1+64+1;
    if(canonicalLength<1||canonicalLength>=768||
       source[canonicalLength-1]!='\n'||
       used-canonicalLength!=resLength||
       reservation[resLength-1]!='\n')return 87;
    char mac[65]={0};
    memcpy(mac,reservation+sizeof("reservationMac=")-1,64);
    if(!bbx_reviewed_lowerhex(mac,64))return 87;
    char canonical[768]={0};
    memcpy(canonical,source,canonicalLength);
    BBXPreissuedReview review={0};
    if(!bbx_parse_preissued_review(canonical,canonicalLength,&review))
        return 87;
    /* Local native signing policy is narrower than the generic reviewed
       contract: only the known 39-byte synthetic fixture may be authorized.
       Neither caller-controlled note bytes nor real files can be signed. */
    static const char expectedSyntheticSHA[]=
        "661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3";
    if(review.byteLength!=39||
       strcmp(review.sha256,expectedSyntheticSHA)!=0)
        return 87;
    /* Refuse an already consumed or unverifiable nonce BEFORE prompting.
       This check never authorizes signing: the post-consent O_EXCL claim is
       still required for cross-process atomicity. */
    const int beforeDir=bbx_test_controller_signing_directory();
    if(beforeDir<0)return 87;
    const BBXReplayObservation prior=bbx_reviewed_replay_observe(
        beforeDir,review.nonce,review.transactionId);
    if(close(beforeDir)!=0)return 87;
    if(prior==BBX_REPLAY_MATCHING_MARKER)return 88; // exact duplicate
    if(prior!=BBX_REPLAY_NO_MARKER)return 87; // unsafe evidence
    // Verify actual HMAC chain and transaction reservation, NOT merely the
    // caller-provided hex digest. Node holds this test key; compromised Node
    // remains within the threat model's explicitly unprotected boundary.
    if(!bbx_test_verify_native_audit(auditDirectory,&review,mac))return 87;
    struct timespec clockValue={0};
    if(clock_gettime(CLOCK_REALTIME,&clockValue)!=0 ||
       clockValue.tv_sec<0)return 87;
    const int64_t now=(int64_t)clockValue.tv_sec*1000+
                      clockValue.tv_nsec/1000000;
    if(now<review.issuedAt||now>=review.expiresAt)return 87;
    /* Sign nothing until the operator approves THIS validated review. */
    if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;
    if(clock_gettime(CLOCK_REALTIME,&clockValue)!=0)return 87;
    const int64_t afterApproval=(int64_t)clockValue.tv_sec*1000+
                                clockValue.tv_nsec/1000000;
    if(afterApproval<review.issuedAt||afterApproval>=review.expiresAt)
        return 87;
    /* Touch ID is asynchronous. Fail closed if the durable audit was
       modified, truncated, or advanced while the operator was deciding.
       This is a fresh validation, not an assurance against an adversary
       holding Node's audit HMAC key or racing a same-user filesystem. */
    if(!bbx_test_verify_native_audit(auditDirectory,&review,mac))
        return 87;
    /* Native consent is single-use: consume the nonce DURABLY before
       using the Keychain signing key, even if the signature/ACK fails.
       This is a separate native evidence boundary, not Node HMAC proof. */
    const int signingDir=bbx_test_controller_signing_directory();
    if(signingDir<0)return 87;
    const BBXReplayDecision reserved=bbx_reviewed_replay_reserve(
        signingDir,review.nonce,review.transactionId);
    if(close(signingDir)!=0||reserved!=BBX_REPLAY_FRESH_COMMITTED)
        return 87;

    OSStatus found=errSecSuccess;
    SecKeyRef privateKey=findPrivateKey(&found);
    if(!privateKey)return 87;
    if(!validRsa2048(privateKey)){CFRelease(privateKey);return 87;}
    const char domain[]="bbx-reviewed-controller-rsa-pss-v1\n";
    NSMutableData *message=[NSMutableData dataWithBytes:domain
                                                    length:sizeof(domain)-1];
    [message appendBytes:source length:used];
    CFErrorRef error=NULL;
    CFDataRef signature=SecKeyCreateSignature(privateKey,
        kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
        (CFDataRef)message,&error);
    CFRelease(privateKey);
    if(error)CFRelease(error);
    if(!signature)return 87;
    const bool valid=CFDataGetLength(signature)==256;
    if(!valid){CFRelease(signature);return 87;}
    const unsigned char *sig=CFDataGetBytePtr(signature);
    char hex[513]={0};
    const char alphabet[]="0123456789abcdef";
    for(size_t i=0;i<256;i++){
        hex[2*i]=alphabet[sig[i]>>4];
        hex[2*i+1]=alphabet[sig[i]&15];
    }
    CFRelease(signature);
    if(fwrite(source,1,used,stdout)!=used)return 87;
    if(fprintf(stdout,"controllerSig=%s\n",hex)!=
       (int)(sizeof("controllerSig=")-1+512+1))return 87;
    if(fflush(stdout)!=0)return 87;
    return 0;
}
int main(int argc,const char *argv[]){
    @autoreleasepool {
        if(argc<2||argc>3)return 90;
        if(argc==2&&strcmp(argv[1],"provision")==0)return provision();
        if(argc==2&&strcmp(argv[1],"public")==0)return exportPublic();
        if(strcmp(argv[1],"sign")==0)
            return argc==3?signFixedSyntheticReview(argv[2]):87;
        return 90;
    }
}
