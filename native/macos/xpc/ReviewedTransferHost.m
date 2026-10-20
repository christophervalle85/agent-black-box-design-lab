/*
 * EXPERIMENTAL v0.8 — signed native-host Touch ID -> XPC reviewed receipt.
 *
 * One fixed in-binary synthetic byte snapshot. The NATIVE signed host owns
 * the review, LAContext and the XPC connection; Node never supplies an
 * "approved" flag, snapshot path, user bytes or bearer token. This is NOT
 * connected to the audited controller or production MCP operations.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "PeerRequirementGate.h"
#include "ReviewedTransactionContract.h"
#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF
#include "ReviewedTransactionHandoff.h"
#endif
#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF
#include "ReviewedTransactionSignedAuthority.h"
#endif
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
#if !defined(BBX_TEST_DURABLE_REPLAY) || !defined(BBX_TEST_RSA_CONTROLLER_HANDOFF)
#error "Worker restart requires the RSA-signed durable test host."
#endif
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#endif
#ifdef BBX_TEST_CRASH_RECONCILE
#if !defined(BBX_TEST_DURABLE_WORKER_RESTART)
#error "Crash reconciliation requires signed native worker restart diagnostics."
#endif
#endif

static const unsigned char fixture[]="BBX synthetic Touch ID reviewed bytes.\n";
static const char target[]="bbx-test-reviewed.txt";
static const char serviceID[]="dev.agentblackbox.xpc-snapshot-receipt.worker";
#define REVIEW_LIFETIME_MS 60000

typedef struct {
    char reviewId[37];
    char nonce[37];
    char sha256[65];
    char transactionId[65];
    int64_t issuedAt;
    int64_t expiresAt;
    uint64_t size;
} NativeReview;
static int64_t nowMs(void){
    struct timespec t={0};
    if(clock_gettime(CLOCK_REALTIME,&t)!=0 || t.tv_sec<0 ||
       t.tv_sec>INT64_MAX/1000-1)return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static void randomUuid4(char text[37]){
    unsigned char random[16];
    const char digits[]="0123456789abcdef";
    arc4random_buf(random,sizeof(random));
    random[6]=(unsigned char)((random[6]&15)|0x40);
    random[8]=(unsigned char)((random[8]&63)|0x80);
    size_t next=0;
    for(size_t i=0;i<sizeof(random);i++){
        if(i==4||i==6||i==8||i==10)text[next++]='-';
        text[next++]=digits[random[i]>>4];
        text[next++]=digits[random[i]&15];
    }
    text[36]='\0';
    if(memset_s(random,sizeof(random),0,sizeof(random))!=0)abort();
}
static bool hashBytes(const unsigned char *bytes,size_t count,char output[65]){
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    const char alphabet[]="0123456789abcdef";
    if(!CC_SHA256(bytes,(CC_LONG)count,hash))return false;
    for(size_t i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        output[2*i]=alphabet[hash[i]>>4];
        output[2*i+1]=alphabet[hash[i]&15];
    }
    output[64]='\0';
    if(memset_s(hash,sizeof(hash),0,sizeof(hash))!=0)abort();
    return true;
}
static bool reviewIsExact(const NativeReview *review){
    if(!review || review->size!=sizeof(fixture)-1 ||
       review->size<1 || review->size>2000 ||
       review->issuedAt<0 ||
       review->issuedAt>INT64_MAX-REVIEW_LIFETIME_MS ||
       review->expiresAt!=review->issuedAt+REVIEW_LIFETIME_MS)
        return false;
    const int64_t now=nowMs();
    if(now<review->issuedAt || now>=review->expiresAt)return false;
    char actual[65];
    if(!hashBytes(fixture,sizeof(fixture)-1,actual))return false;
    char transactionId[65];
    const bool okay=bbx_reviewed_transaction_id(
        review->reviewId,"import",target,review->size,
        review->sha256,review->nonce,review->issuedAt,review->expiresAt,
        transactionId);
    const bool match=okay && memcmp(actual,review->sha256,65)==0 &&
        bbx_reviewed_equal_hash(transactionId,review->transactionId);
    if(memset_s(actual,sizeof(actual),0,sizeof(actual))!=0)abort();
    return match;
}
static bool prepareReview(NativeReview *review){
    if(!review)return false;
    memset(review,0,sizeof(*review));
    randomUuid4(review->nonce);
    randomUuid4(review->reviewId);
    if(!hashBytes(fixture,sizeof(fixture)-1,review->sha256))return false;
    review->size=sizeof(fixture)-1;
    review->issuedAt=nowMs();
    if(review->issuedAt<0 || review->issuedAt>INT64_MAX-REVIEW_LIFETIME_MS)
        return false;
    review->expiresAt=review->issuedAt+REVIEW_LIFETIME_MS;
    if(!bbx_reviewed_transaction_id(
        review->reviewId,"import",target,review->size,
        review->sha256,review->nonce,review->issuedAt,review->expiresAt,
        review->transactionId))return false;
    return reviewIsExact(review);
}
#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF
static bool importPreissuedReview(NativeReview *out){
    BBXPreissuedReview preissued={0};
    if(!bbx_read_preissued_review(stdin,&preissued))return false;
    memset(out,0,sizeof(*out));
    memcpy(out->reviewId,preissued.reviewId,sizeof(out->reviewId));
    memcpy(out->nonce,preissued.nonce,sizeof(out->nonce));
    memcpy(out->sha256,preissued.sha256,sizeof(out->sha256));
    memcpy(out->transactionId,preissued.transactionId,sizeof(out->transactionId));
    out->issuedAt=preissued.issuedAt;
    out->expiresAt=preissued.expiresAt;
    out->size=preissued.byteLength;
    return reviewIsExact(out);
}
#endif

#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF
static bool importSignedPreissuedReview(NativeReview *out){
    BBXPreissuedReview preissued={0};
    if(!bbx_read_signed_preissued_review(stdin,&preissued))return false;
    memset(out,0,sizeof(*out));
    memcpy(out->reviewId,preissued.reviewId,sizeof(out->reviewId));
    memcpy(out->nonce,preissued.nonce,sizeof(out->nonce));
    memcpy(out->sha256,preissued.sha256,sizeof(out->sha256));
    memcpy(out->transactionId,preissued.transactionId,sizeof(out->transactionId));
    out->issuedAt=preissued.issuedAt;
    out->expiresAt=preissued.expiresAt;
    out->size=preissued.byteLength;
    return reviewIsExact(out);
}
#endif

static int authenticateReview(const NativeReview *review){
    @autoreleasepool {
        if(!reviewIsExact(review))return 87;
        LAContext *context=[[LAContext alloc]init];
        context.touchIDAuthenticationAllowableReuseDuration=0;
        NSError *preflight=nil;
        const LAPolicy policy=LAPolicyDeviceOwnerAuthenticationWithBiometrics;
        if(![context canEvaluatePolicy:policy error:&preflight]){
            [context invalidate];
            [context release];
            return 82;
        }
        // The native host constructs ALL review fields, not untrusted argv.
        // The long SHA string may be visually truncated by macOS: this is
        // NOT yet a production immutable consent-screen design.
        NSString *reason=[NSString stringWithFormat:
            @"Agent Black Box TEST ONLY. Import %s, %llu bytes, SHA256 %s. No real files are changed.",
            target,(unsigned long long)review->size,review->sha256];
        dispatch_semaphore_t done=dispatch_semaphore_create(0);
        __block BOOL accepted=NO;
        __block BOOL cancelled=NO;
        [context evaluatePolicy:policy localizedReason:reason
                           reply:^(BOOL success,NSError *error){
            accepted=success && error==nil;
            cancelled=error &&
                [error.domain isEqualToString:LAErrorDomain] &&
                error.code==LAErrorUserCancel;
            dispatch_semaphore_signal(done);
        }];
        const long result=dispatch_semaphore_wait(done,
            dispatch_time(DISPATCH_TIME_NOW,25LL*NSEC_PER_SEC));
        if(result!=0){
            [context invalidate];
            [context release];
            return 84;
        }
        [context invalidate];
        [context release];
        // Authorization is useless if it expired during the biometric UI.
        if(accepted)return reviewIsExact(review)?0:87;
        return cancelled?83:87;
    }
}
static xpc_connection_t openWorker(void){
    xpc_connection_t peer=xpc_connection_create(serviceID,
        dispatch_get_global_queue(QOS_CLASS_DEFAULT,0));
    if(!peer)return NULL;
    if(bbx_install_same_team_peer_requirement(peer,serviceID)!=0){
        xpc_connection_cancel(peer);
        xpc_release(peer);
        return NULL;
    }
    xpc_connection_set_event_handler(peer,^(xpc_object_t event){
        (void)event;
    });
    xpc_connection_resume(peer);
    return peer;
}
static bool statusIs(xpc_connection_t peer,const NativeReview *review,
                     const unsigned char *bytes,size_t count,
                     const char *expected,const char *mutation){
    if(!reviewIsExact(review))return false;
    xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
    if(!request)return false;
    xpc_dictionary_set_string(request,"method","reviewed_snapshot_receipt");
    xpc_dictionary_set_uint64(request,"version",BBX_REVIEWED_VERSION);
    xpc_dictionary_set_string(request,"transactionId",review->transactionId);
    xpc_dictionary_set_string(request,"name",target);
    xpc_dictionary_set_string(request,"operation","import");
    xpc_dictionary_set_string(request,"nonce",review->nonce);
    xpc_dictionary_set_string(request,"reviewId",review->reviewId);
    xpc_dictionary_set_string(request,"sha256",review->sha256);
    xpc_dictionary_set_uint64(request,"byteLength",review->size);
    xpc_dictionary_set_int64(request,"issuedAt",review->issuedAt);
    xpc_dictionary_set_int64(request,"expiresAt",review->expiresAt);
    xpc_dictionary_set_data(request,"payload",bytes,count);
    // Controlled wire-level attack fixtures. All remain syntactically typed
    // XPC dictionaries; the signed worker must reject their identity.
    if(mutation){
        if(strcmp(mutation,"bad-transaction-id")==0){
            char bad[65];
            memcpy(bad,review->transactionId,sizeof(bad));
            bad[0]=bad[0]=='f'?'e':'f';
            xpc_dictionary_set_string(request,"transactionId",bad);
        }else if(strcmp(mutation,"bad-version")==0){
            xpc_dictionary_set_uint64(request,"version",2);
        }else if(strcmp(mutation,"bad-note")==0){
            xpc_dictionary_set_string(request,"name","bbx-test-other.txt");
        }else if(strcmp(mutation,"bad-nonce")==0){
            char bad[37];
            memcpy(bad,review->nonce,sizeof(bad));
            bad[0]=bad[0]=='f'?'e':'f';
            xpc_dictionary_set_string(request,"nonce",bad);
        }else{
            xpc_release(request);
            return false;
        }
    }
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,request);
    xpc_release(request);
    if(!reply)return false;
    __block size_t fields=0;
    __block bool schema=true;
    if(xpc_get_type(reply)==XPC_TYPE_DICTIONARY)
        xpc_dictionary_apply(reply,^bool(const char *key,xpc_object_t value){
            fields++;
            if(strcmp(key,"status")!=0 || xpc_get_type(value)!=XPC_TYPE_STRING)
                schema=false;
            return true;
        });
    else schema=false;
    const char *got=schema && fields==1 ?
        xpc_dictionary_get_string(reply,"status"):NULL;
    bool okay=got && strcmp(got,expected)==0;
    xpc_release(reply);
    return okay;
}
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
typedef struct {
    uint64_t pid;
    char instance[33];
} BBXTestWorkerInstance;

/* Strict exact three-field reply; all evidence comes from the OS-verified
 * signed XPC worker, not argv, a PID file or agent-controlled metadata. */
static bool bbx_test_worker_command(xpc_connection_t peer,
    const char *method,const char *expected,BBXTestWorkerInstance *out){
    if(!peer||!method||!expected||!out)return false;
    xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
    if(!request)return false;
    xpc_dictionary_set_string(request,"method",method);
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,request);
    xpc_release(request);
    if(!reply)return false;
    __block unsigned count=0;
    __block bool exact=true;
    if(xpc_get_type(reply)==XPC_TYPE_DICTIONARY)
        xpc_dictionary_apply(reply,^bool(const char *key,xpc_object_t value){
            count++;
            const xpc_type_t type=xpc_get_type(value);
            if(!((strcmp(key,"status")==0&&type==XPC_TYPE_STRING)||
                 (strcmp(key,"workerPid")==0&&type==XPC_TYPE_UINT64)||
                 (strcmp(key,"workerInstance")==0&&type==XPC_TYPE_STRING)))
                exact=false;
            return true;
        });
    else exact=false;
    const char *status=exact&&count==3?
        xpc_dictionary_get_string(reply,"status"):NULL;
    const char *instance=exact&&count==3?
        xpc_dictionary_get_string(reply,"workerInstance"):NULL;
    const uint64_t pid=exact&&count==3?
        xpc_dictionary_get_uint64(reply,"workerPid"):0;
    const bool valid=status&&strcmp(status,expected)==0 &&
        instance&&bbx_reviewed_lowerhex(instance,32) &&
        pid>1 && pid<INT_MAX;
    if(valid){
        out->pid=pid;
        memcpy(out->instance,instance,sizeof(out->instance));
    }
    xpc_release(reply);
    return valid;
}
/*
 * A deliberate process termination must actually occur: a new XPC
 * connection with a different PID is insufficient by itself, because
 * launchd could create multiple service processes. Verify ESRCH on the
 * original worker PID before reconnecting.
 */
static bool bbx_test_force_restart_and_reject(const NativeReview *review){
    if(!reviewIsExact(review))return false;
    xpc_connection_t first=openWorker();
    if(!first)return false;
    BBXTestWorkerInstance before={0},exitAck={0};
    const bool began=bbx_test_worker_command(first,"bbx_test_worker_identity",
                                              "READY",&before);
    const bool requested=began&&bbx_test_worker_command(
        first,"bbx_test_worker_exit","EXITING",&exitAck);
    xpc_connection_cancel(first);
    xpc_release(first);
    if(!requested||before.pid!=exitAck.pid||
       strcmp(before.instance,exitAck.instance)!=0)return false;

    bool oldGone=false;
    for(unsigned attempt=0;attempt<60;attempt++){
        errno=0;
        if(kill((pid_t)before.pid,0)==-1&&errno==ESRCH){
            oldGone=true;
            break;
        }
        usleep(100000);
    }
    if(!oldGone)return false;

    /* The new worker must show a fresh OS PID AND per-process random token.
     * It then revalidates the same signed transaction and must report REPLAY
     * using its sandbox-owned durable marker, without running Touch ID again. */
    for(unsigned attempt=0;attempt<8;attempt++){
        xpc_connection_t fresh=openWorker();
        if(!fresh)return false;
        BBXTestWorkerInstance after={0};
        const bool ready=bbx_test_worker_command(
            fresh,"bbx_test_worker_identity","READY",&after);
        const bool distinct=ready && after.pid!=before.pid &&
            strcmp(after.instance,before.instance)!=0;
        const bool denied=distinct&&statusIs(fresh,review,fixture,
            sizeof(fixture)-1,"REPLAY",NULL);
        xpc_connection_cancel(fresh);
        xpc_release(fresh);
        if(denied)return true;
        /* A different worker that returned ACCEPTED is a hard failure;
         * retry loops cannot turn a replay failure into acceptance. */
        if(ready)return false;
        usleep(150000);
    }
    return false;
}
#endif


#ifdef BBX_TEST_CRASH_RECONCILE
/* The only replay evidence accepted by this host comes from the signed XPC
 * worker, never a path or status supplied over stdin. Diagnostic responses
 * carry exactly a status, worker PID, and unpredictable process instance. */
static bool bbx_test_receipt_diagnostic(
    xpc_connection_t peer,const char *method,const NativeReview *review,
    const char *phase,const char *expected,BBXTestWorkerInstance *out){
    if(!peer||!method||!review||!expected||!out ||
       !reviewIsExact(review))return false;
    xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
    if(!request)return false;
    xpc_dictionary_set_string(request,"method",method);
    xpc_dictionary_set_string(request,"nonce",review->nonce);
    xpc_dictionary_set_string(request,"transactionId",review->transactionId);
    if(phase)xpc_dictionary_set_string(request,"phase",phase);
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,request);
    xpc_release(request);
    if(!reply)return false;
    __block unsigned count=0;
    __block bool schema=true;
    if(xpc_get_type(reply)==XPC_TYPE_DICTIONARY)
        xpc_dictionary_apply(reply,^bool(const char *key,xpc_object_t value){
            count++;
            const xpc_type_t type=xpc_get_type(value);
            if(!((strcmp(key,"status")==0&&type==XPC_TYPE_STRING)||
                 (strcmp(key,"workerPid")==0&&type==XPC_TYPE_UINT64)||
                 (strcmp(key,"workerInstance")==0&&type==XPC_TYPE_STRING)))
                schema=false;
            return true;
        });
    else schema=false;
    const char *status=schema&&count==3?
        xpc_dictionary_get_string(reply,"status"):NULL;
    const char *instance=schema&&count==3?
        xpc_dictionary_get_string(reply,"workerInstance"):NULL;
    const uint64_t pid=schema&&count==3?
        xpc_dictionary_get_uint64(reply,"workerPid"):0;
    const bool valid=status&&strcmp(status,expected)==0&&
        instance&&bbx_reviewed_lowerhex(instance,32)&&
        pid>1&&pid<INT_MAX;
    if(valid){
        out->pid=pid;
        memcpy(out->instance,instance,sizeof(out->instance));
    }
    xpc_release(reply);
    return valid;
}
/*
 * A crashed worker cannot acknowledge a receipt. Even if its durable nonce
 * marker exists, this is not an OS file import, approval or commit receipt.
 * No retry and no write are performed after the crash.
 */
static bool bbx_test_crash_and_observe(
    const NativeReview *review,const char *phase){
    if(!reviewIsExact(review) ||
       (strcmp(phase,"before")!=0&&strcmp(phase,"after")!=0))
        return false;
    xpc_connection_t first=openWorker();
    if(!first)return false;
    BBXTestWorkerInstance before={0},armed={0};
    const bool initialized=bbx_test_worker_command(
        first,"bbx_test_worker_identity","READY",&before);
    const bool ready=initialized&&bbx_test_receipt_diagnostic(
        first,"bbx_test_arm_receipt_crash",review,phase,"ARMED",&armed);
    if(!ready||before.pid!=armed.pid||
       strcmp(before.instance,armed.instance)!=0){
        xpc_connection_cancel(first);
        xpc_release(first);
        return false;
    }
    /* A correctly validated request is sent ONLY once. An ACK here is
       failure because the configured worker should have exited first. */
    const bool incorrectlyAcknowledged=statusIs(first,review,fixture,
        sizeof(fixture)-1,"ACCEPTED",NULL);
    xpc_connection_cancel(first);
    xpc_release(first);
    if(incorrectlyAcknowledged)return false;
    bool oldExited=false;
    for(unsigned n=0;n<60;n++){
        errno=0;
        if(kill((pid_t)before.pid,0)==-1&&errno==ESRCH){
            oldExited=true;
            break;
        }
        usleep(100000);
    }
    if(!oldExited)return false;
    const char *expected=strcmp(phase,"before")==0?
        "NO_MARKER":"MATCHING_MARKER";
    for(unsigned attempt=0;attempt<8;attempt++){
        xpc_connection_t next=openWorker();
        if(!next)return false;
        BBXTestWorkerInstance restarted={0},observed={0};
        const bool readyAgain=bbx_test_worker_command(
            next,"bbx_test_worker_identity","READY",&restarted);
        const bool different=readyAgain&&restarted.pid!=before.pid&&
            strcmp(restarted.instance,before.instance)!=0;
        const bool evidence=different&&bbx_test_receipt_diagnostic(
            next,"bbx_test_observe_receipt",review,NULL,expected,&observed);
        const bool bound=evidence&&restarted.pid==observed.pid&&
            strcmp(restarted.instance,observed.instance)==0;
        xpc_connection_cancel(next);
        xpc_release(next);
        if(bound)return true;
        /* Observed another running worker with mismatching durable evidence:
           fail immediately, never guess or repeat the transaction. */
        if(readyAgain)return false;
        usleep(150000);
    }
    return false;
}
#endif

int main(int argc,const char *argv[]){
#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF
    /* Distinct allowlists prevent invoking legacy / no-auth modes on the
       signed-authority builds, including the persistent replay diagnostic. */
#ifdef BBX_TEST_CRASH_RECONCILE
    /* Crash-only builds remain restricted. The combined Keychain test
       explicitly opts into replay/restart controls for its full suite. */
    if(argc!=2 || (strcmp(argv[1],"handoff-rsa-durable-invalid")!=0 &&
                   strcmp(argv[1],"handoff-rsa-crash-before")!=0 &&
                   strcmp(argv[1],"handoff-rsa-crash-after")!=0
#ifdef BBX_TEST_KEYCHAIN_FULL_SUITE
                   && strcmp(argv[1],"handoff-rsa-durable-approved")!=0
                   && strcmp(argv[1],"handoff-rsa-durable-replay")!=0
                   && strcmp(argv[1],"handoff-rsa-durable-restart")!=0
#endif
                   )){
#elif defined(BBX_TEST_DURABLE_REPLAY)
    if(argc!=2 || (strcmp(argv[1],"handoff-rsa-durable-approved")!=0 &&
                   strcmp(argv[1],"handoff-rsa-durable-invalid")!=0 &&
                   strcmp(argv[1],"handoff-rsa-durable-replay")!=0
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
                   && strcmp(argv[1],"handoff-rsa-durable-restart")!=0
#endif
                   )){
#else
    if(argc!=2 || (strcmp(argv[1],"handoff-rsa-approved")!=0 &&
                   strcmp(argv[1],"handoff-rsa-invalid")!=0)){
#endif
#else
    if(argc!=2 || (strcmp(argv[1],"approved")!=0 &&
                   strcmp(argv[1],"cancel")!=0 &&
                   strcmp(argv[1],"expired")!=0
#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF
                   && strcmp(argv[1],"handoff-approved")!=0 &&
                   strcmp(argv[1],"handoff-invalid")!=0
#endif
                   )){
#endif
        puts("BBX_REVIEWED_XPC_BAD_ARGS");
        return 90;
    }
    NativeReview review;
#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF
    const bool external=strncmp(argv[1],"handoff-",8)==0;
    if(external){
        // Validated entirely before Touch ID or XPC. The RSA public key is
        // embedded before signing the diagnostic native app, not in stdin.
#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF
        const bool valid=importSignedPreissuedReview(&review);
#ifdef BBX_TEST_DURABLE_REPLAY
        const bool negative=strcmp(argv[1],"handoff-rsa-durable-invalid")==0;
#else
        const bool negative=strcmp(argv[1],"handoff-rsa-invalid")==0;
#endif
#else
        const bool valid=importPreissuedReview(&review);
        const bool negative=strcmp(argv[1],"handoff-invalid")==0;
#endif
        if(negative){
            if(valid){
                puts("BBX_REVIEWED_XPC_UNEXPECTED_VALID_HANDOFF");
                return 87;
            }
#ifdef BBX_TEST_DURABLE_REPLAY
            puts("BBX_REVIEWED_XPC_INVALID_DURABLE_RSA_HANDOFF_NO_AUTH_NO_XPC");
#elif defined(BBX_TEST_RSA_CONTROLLER_HANDOFF)
            puts("BBX_REVIEWED_XPC_INVALID_RSA_HANDOFF_NO_AUTH_NO_XPC");
#else
            puts("BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC");
#endif
            return 0;
        }
        if(!valid){
            puts("BBX_REVIEWED_XPC_HANDOFF_DENIED");
            return 87;
        }
    }else
#endif
    if(!prepareReview(&review)){
        puts("BBX_REVIEWED_XPC_SETUP_DENIED");
        return 87;
    }
    // Standalone clock-negative fixture; NO LA prompt and NO XPC dispatch.
    if(strcmp(argv[1],"expired")==0){
        review.issuedAt-=REVIEW_LIFETIME_MS+1;
        review.expiresAt-=REVIEW_LIFETIME_MS+1;
        if(reviewIsExact(&review)){
            puts("BBX_REVIEWED_XPC_EXPIRED_UNEXPECTEDLY_VALID");
            return 87;
        }
        puts("BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH");
        return 0;
    }
    const NativeReview committed=review; // Immutable local pre-auth snapshot.
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
    if(strcmp(argv[1],"handoff-rsa-durable-restart")==0){
        if(!bbx_test_force_restart_and_reject(&review)){
            puts("BBX_REVIEWED_XPC_WORKER_RESTART_NOT_PROVEN");
            return 87;
        }
        puts("BBX_REVIEWED_XPC_WORKER_RESTART_REPLAY_DENIED");
        return 0;
    }
#endif
#ifdef BBX_TEST_DURABLE_REPLAY
    /*
     * NEGATIVE-ONLY diagnostic: a second independently launched native
     * host submits the identical SIGNED transaction without another biometric
     * prompt, and passes ONLY if the worker returns REPLAY. This can never
     * produce a success/transfer receipt; on unexpected ACCEPTED it fails.
     */
    if(strcmp(argv[1],"handoff-rsa-durable-replay")==0){
        if(!reviewIsExact(&review))return 87;
        xpc_connection_t replayPeer=openWorker();
        if(!replayPeer)return 85;
        const bool denied=statusIs(replayPeer,&review,fixture,
                                   sizeof(fixture)-1,"REPLAY",NULL);
        xpc_connection_cancel(replayPeer);
        xpc_release(replayPeer);
        if(!denied){
            puts("BBX_REVIEWED_XPC_DURABLE_REPLAY_NOT_DENIED");
            return 87;
        }
        puts("BBX_REVIEWED_XPC_DURABLE_REPLAY_REJECTED");
        return 0;
    }
#endif
    const int auth=authenticateReview(&review);
    // Touch ID can approve only the exact review metadata it was shown.
    // Fail closed if nonce, ID, expiry, size or digest changed in memory.
    if(memcmp(&review,&committed,sizeof(review))!=0){
        puts("BBX_REVIEWED_XPC_REVIEW_CHANGED");
        return 87;
    }
    if(strcmp(argv[1],"cancel")==0){
        if(auth==83){
            puts("BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH");
            return 0;
        }
        puts("BBX_REVIEWED_XPC_CANCEL_TEST_NOT_ACCEPTED");
        return 87;
    }
    if(auth!=0){
        puts(auth==82?"BBX_REVIEWED_XPC_TOUCHID_UNAVAILABLE":
             auth==84?"BBX_REVIEWED_XPC_TOUCHID_TIMEOUT":
             "BBX_REVIEWED_XPC_AUTH_NOT_APPROVED");
        return 87;
    }
    // The ONLY state-changing operation can connect to XPC only below the
    // biometric-success check in the same signed process.
    if(!reviewIsExact(&review))return 87;
#ifdef BBX_TEST_CRASH_RECONCILE
    if(strcmp(argv[1],"handoff-rsa-crash-before")==0 ||
       strcmp(argv[1],"handoff-rsa-crash-after")==0){
        const bool beforeCrash=strcmp(argv[1],"handoff-rsa-crash-before")==0;
        if(!bbx_test_crash_and_observe(&review,
                                      beforeCrash?"before":"after")){
            puts("BBX_REVIEWED_XPC_CRASH_RECONCILIATION_NOT_PROVEN");
            return 87;
        }
        puts(beforeCrash?
            "BBX_REVIEWED_XPC_CRASH_BEFORE_NO_MARKER_NO_RETRY":
            "BBX_REVIEWED_XPC_CRASH_AFTER_SPENT_NO_ACK_NO_RETRY");
        return 0;
    }
#endif
    xpc_connection_t peer=openWorker();
    if(!peer){
        puts("BBX_REVIEWED_XPC_OS_GATE_UNAVAILABLE");
        return 85;
    }
    unsigned char changed[sizeof(fixture)-1];
    memcpy(changed,fixture,sizeof(changed));
    changed[0]^=1;
    // One Touch ID review: changed bytes MUST be rejected; exact bytes
    // may be accepted once, and replay must then be rejected.
    bool valid=
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "BAD_REQUEST","bad-transaction-id") &&
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "BAD_REQUEST","bad-version") &&
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "BAD_REQUEST","bad-note") &&
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "BAD_REQUEST","bad-nonce") &&
               statusIs(peer,&review,changed,sizeof(changed),
                        "DIGEST_MISMATCH",NULL) &&
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "ACCEPTED",NULL) &&
               statusIs(peer,&review,fixture,sizeof(fixture)-1,
                        "REPLAY",NULL);
    if(memset_s(changed,sizeof(changed),0,sizeof(changed))!=0)abort();
    xpc_connection_cancel(peer);
    xpc_release(peer);
    if(!valid){
        puts("BBX_REVIEWED_XPC_TRANSACTION_NOT_ACCEPTED");
        return 87;
    }
#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF
    if(strcmp(argv[1],"handoff-approved")==0){
        puts("BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED");
        return 0;
    }
#endif
#ifdef BBX_TEST_DURABLE_REPLAY
    if(strcmp(argv[1],"handoff-rsa-durable-approved")==0){
        puts("BBX_REVIEWED_XPC_RSA_DURABLE_TOUCHID_ACCEPTED");
        return 0;
    }
#endif
#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF
    if(strcmp(argv[1],"handoff-rsa-approved")==0){
        puts("BBX_REVIEWED_XPC_RSA_PREISSUED_TOUCHID_ACCEPTED");
        return 0;
    }
#endif
    puts("BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED");
    return 0;
}
