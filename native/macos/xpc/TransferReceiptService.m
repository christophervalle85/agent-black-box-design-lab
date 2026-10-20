/*
 * EXPERIMENTAL v0.8: synthetic-only XPC data receipt worker.
 * The service cannot open documents, create files, or return payload bytes.
 * No trusted peer/approval assertion: ad-hoc test binaries are not
 * production same-Team-ID identities. Replay cache is process-local ONLY.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef BBX_TEST_DURABLE_REPLAY
#ifndef BBX_TEST_NATIVE_REVIEWED_RECEIPT
#error "Durable replay requires exact reviewed-transaction validation."
#endif
#ifndef BBX_TEST_SIGNED_PEER_REQUIREMENT
#error "Durable replay requires OS-enforced signed incoming host identity."
#endif
#import <Foundation/Foundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "ReviewedDurableReplay.h"
#include "ReviewedDurableReplayDirectory.h"
#endif
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
#include "ReviewedWorkerRestartTest.h"
#endif
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
#include <time.h>
#include <limits.h>
#include "ReviewedTransactionContract.h"
#endif
#ifdef BBX_TEST_SIGNED_INBOUND_EVIDENCE
#include <unistd.h>
#endif
#ifdef BBX_TEST_SIGNED_PEER_REQUIREMENT
#include "PeerRequirementGate.h"
#endif

#define BBX_MAX_PAYLOAD 2000
#define BBX_MAX_NONCES 64

static dispatch_queue_t nonceQueue;
#ifdef BBX_TEST_CRASH_RECONCILE
#include "ReviewedCrashReconcileTest.h"
#endif
static char seen[BBX_MAX_NONCES][37];
static size_t seenCount=0;
#ifdef BBX_TEST_SIGNED_INBOUND_EVIDENCE
/* ONLY the signed, disposable on-Mac inbound-peer test includes this.
 * Not an audit counter or an actual review authorization token. */
static uint64_t acceptedMessageCount=0;
#endif

static bool lowerHex(const char *s,size_t n){
    if(!s || strnlen(s,n+1)!=n)return false;
    for(size_t i=0;i<n;i++){
        const char c=s[i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    }
    return true;
}
static bool testName(const char *s){
    if(!s)return false;
    size_t n=strnlen(s,80);
    if(n<14||n>64||strncmp(s,"bbx-test-",9)!=0 ||
       strcmp(s+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        char c=s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
static bool exactKeys(xpc_object_t request){
    __block unsigned count=0;
    __block bool valid=true;
    xpc_dictionary_apply(request,^bool(const char *key,xpc_object_t value){
        (void)value;
        if(strcmp(key,"method")!=0 && strcmp(key,"name")!=0 &&
           strcmp(key,"nonce")!=0 && strcmp(key,"sha256")!=0 &&
           strcmp(key,"payload")!=0
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
           && strcmp(key,"operation")!=0 &&
           strcmp(key,"reviewId")!=0 &&
           strcmp(key,"byteLength")!=0 &&
           strcmp(key,"issuedAt")!=0 &&
           strcmp(key,"expiresAt")!=0 &&
           strcmp(key,"version")!=0 &&
           strcmp(key,"transactionId")!=0
#endif
           )valid=false;
        count++;
        return true;
    });
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
    return valid && count==12;
#else
    return valid && count==5;
#endif
}
static bool isType(xpc_object_t request,const char *key,xpc_type_t type){
    xpc_object_t item=xpc_dictionary_get_value(request,key);
    return item && xpc_get_type(item)==type;
}
static bool digestMatches(const void *data,size_t size,const char *claimed){
    unsigned char actual[CC_SHA256_DIGEST_LENGTH];
    if(!CC_SHA256(data,(CC_LONG)size,actual))return false;
    unsigned difference=0;
    const char chars[]="0123456789abcdef";
    for(size_t i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        difference|=(unsigned char)claimed[2*i] ^
                    (unsigned char)chars[actual[i]>>4];
        difference|=(unsigned char)claimed[2*i+1] ^
                    (unsigned char)chars[actual[i]&15];
    }
    memset_s(actual,sizeof(actual),0,sizeof(actual));
    return difference==0;
}
static void respond(xpc_connection_t peer,xpc_object_t message,const char *status){
    xpc_object_t reply=xpc_dictionary_create_reply(message);
    if(!reply)return;
    xpc_dictionary_set_string(reply,"status",status);
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
}
static void handle(xpc_connection_t peer,xpc_object_t message){
    if(!exactKeys(message) ||
       !isType(message,"method",XPC_TYPE_STRING) ||
       !isType(message,"name",XPC_TYPE_STRING) ||
       !isType(message,"nonce",XPC_TYPE_STRING) ||
       !isType(message,"sha256",XPC_TYPE_STRING) ||
       !isType(message,"payload",XPC_TYPE_DATA)
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
       || !isType(message,"operation",XPC_TYPE_STRING)
       || !isType(message,"reviewId",XPC_TYPE_STRING)
       || !isType(message,"byteLength",XPC_TYPE_UINT64)
       || !isType(message,"issuedAt",XPC_TYPE_INT64)
       || !isType(message,"expiresAt",XPC_TYPE_INT64)
       || !isType(message,"version",XPC_TYPE_UINT64)
       || !isType(message,"transactionId",XPC_TYPE_STRING)
#endif
       ){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
    const char *method=xpc_dictionary_get_string(message,"method");
    const char *name=xpc_dictionary_get_string(message,"name");
    const char *nonce=xpc_dictionary_get_string(message,"nonce");
    const char *sha=xpc_dictionary_get_string(message,"sha256");
    size_t count=0;
    const void *bytes=xpc_dictionary_get_data(message,"payload",&count);
    if(!method ||
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
       strcmp(method,"reviewed_snapshot_receipt")!=0 ||
#else
       strcmp(method,"snapshot_receipt")!=0 ||
#endif
       !testName(name) ||
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
       !bbx_reviewed_uuid4(nonce) ||
#else
       !lowerHex(nonce,32) ||
#endif
       !lowerHex(sha,64) ||
       count<1 || count>BBX_MAX_PAYLOAD || !bytes){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
    const char *operation=xpc_dictionary_get_string(message,"operation");
    const char *reviewId=xpc_dictionary_get_string(message,"reviewId");
    const uint64_t statedSize=xpc_dictionary_get_uint64(message,"byteLength");
    const int64_t issued=xpc_dictionary_get_int64(message,"issuedAt");
    const int64_t expires=xpc_dictionary_get_int64(message,"expiresAt");
    const uint64_t version=xpc_dictionary_get_uint64(message,"version");
    const char *transactionId=xpc_dictionary_get_string(message,"transactionId");
    char expectedId[65];
    if(version!=BBX_REVIEWED_VERSION ||
       !operation || strcmp(operation,"import")!=0 ||
       statedSize!=count ||
       !bbx_reviewed_transaction_id(
           reviewId,operation,name,statedSize,sha,nonce,issued,expires,
           expectedId) ||
       !bbx_reviewed_equal_hash(expectedId,transactionId)){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
    struct timespec wall={0};
    if(clock_gettime(CLOCK_REALTIME,&wall)!=0){
        respond(peer,message,"BAD_REQUEST");
        return;
    }
    const int64_t now=(int64_t)wall.tv_sec*1000+wall.tv_nsec/1000000;
    if(now<issued || now>=expires){
        respond(peer,message,"REVIEW_EXPIRED");
        return;
    }
#endif
    if(!digestMatches(bytes,count,sha)){
        respond(peer,message,"DIGEST_MISMATCH");
        return;
    }
#ifdef BBX_TEST_DURABLE_REPLAY
    /*
     * Receipt is ACCEPTED only after atomic create + file and directory
     * fsync. No rollback/cleanup if durability is uncertain. An entirely
     * new worker process still sees the same spent nonce in its container.
     */
    __block const char *status="STORAGE_DENIED";
    dispatch_sync(nonceQueue,^{
#ifdef BBX_TEST_CRASH_RECONCILE
        bbx_test_maybe_crash_receipt(nonce,transactionId,1);
#endif
        const int folder=bbx_replay_directory();
        if(folder<0)return;
        const BBXReplayDecision result=bbx_reviewed_replay_reserve(
            folder,nonce,transactionId);
        close(folder);
#ifdef BBX_TEST_CRASH_RECONCILE
        if(result==BBX_REPLAY_FRESH_COMMITTED)
            bbx_test_maybe_crash_receipt(nonce,transactionId,2);
#endif
        if(result==BBX_REPLAY_FRESH_COMMITTED)status="ACCEPTED";
        else if(result==BBX_REPLAY_ALREADY_SPENT)status="REPLAY";
    });
#else
    // Other test modes retain bounded, process-local replay cache.
    __block const char *status="REPLAY";
    dispatch_sync(nonceQueue,^{
        for(size_t i=0;i<seenCount;i++)
            if(strcmp(seen[i],nonce)==0)return;
        if(seenCount>=BBX_MAX_NONCES){
            status="CAPACITY_EXHAUSTED";
            return;
        }
#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT
        memcpy(seen[seenCount],nonce,37);
#else
        memcpy(seen[seenCount],nonce,33);
#endif
        seenCount++;
        status="ACCEPTED";
    });
#endif
    respond(peer,message,status);
}
static void acceptPeer(xpc_connection_t peer){
#ifdef BBX_TEST_SIGNED_PEER_REQUIREMENT
    // Signed fixture only: the OS checks both same Team ID and the exact
    // native host signing identifier BEFORE delivering any XPC message.
    // Install once, before resume; an unavailable API must fail closed.
    if(bbx_install_same_team_peer_requirement(
        peer,"dev.agentblackbox.xpc-snapshot-receipt.host")!=0){
        xpc_connection_cancel(peer);
        return;
    }
#else
    // Ad-hoc synthetic receipt mode never asserts trusted peer identity.
    // No filesystem mutation or production transfer capability exists.
#endif
    xpc_connection_set_event_handler(peer,^(xpc_object_t event){
        if(xpc_get_type(event)!=XPC_TYPE_DICTIONARY)return;
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
        if(bbx_test_handle_worker_lifecycle(peer,event))return;
#endif
#ifdef BBX_TEST_CRASH_RECONCILE
        if(bbx_test_handle_crash_reconcile_control(peer,event))return;
#endif
#ifdef BBX_TEST_SIGNED_INBOUND_EVIDENCE
        /* Count EVERY OS-delivered dictionary, including malformed ones.
         * An unauthorized peer should never reach this callback at all. */
        __block uint64_t delivered=0;
        dispatch_sync(nonceQueue,^{
            delivered=++acceptedMessageCount;
        });
        const char *operation=xpc_dictionary_get_string(event,"method");
        if(operation && strcmp(operation,"signed_inbound_stats")==0){
            __block unsigned fields=0;
            __block bool onlyMethod=true;
            xpc_dictionary_apply(event,^bool(const char *key,xpc_object_t value){
                (void)value;
                fields++;
                if(strcmp(key,"method")!=0)onlyMethod=false;
                return true;
            });
            xpc_object_t result=xpc_dictionary_create_reply(event);
            if(result){
                if(fields==1 && onlyMethod){
                    xpc_dictionary_set_uint64(result,"delivered",delivered);
                    xpc_dictionary_set_uint64(result,"workerPID",(uint64_t)getpid());
                }
                xpc_connection_send_message(peer,result);
                xpc_release(result);
            }
            return;
        }
#endif
        handle(peer,event);
    });
    xpc_connection_resume(peer);
}
int main(void){
    nonceQueue=dispatch_queue_create("dev.agentblackbox.synthetic-receipt",DISPATCH_QUEUE_SERIAL);
#ifdef BBX_TEST_DURABLE_WORKER_RESTART
    bbx_test_initialize_worker_instance();
#endif
    xpc_main(acceptPeer);
    return 70;
}
