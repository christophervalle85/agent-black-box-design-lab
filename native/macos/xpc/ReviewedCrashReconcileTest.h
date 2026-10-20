/*
 * TEST ONLY: signed-peer gated deterministic worker crash injection and
 * read-only durable nonce observation. No production XPC service includes
 * these methods. The arm request is scoped to an exact nonce+transaction ID
 * and expires with this worker process. No arbitrary PID, path, or bytes.
 *
 * Snapshot statuses are evidence ONLY:
 * MATCHING_MARKER means the exact durable marker was observed.
 * NO_MARKER means no record was observed in the current container snapshot.
 * UNVERIFIABLE means unreadable, corrupt, foreign or unsafe evidence.
 * None permits retry or claims actual user file modification.
 */
#ifndef BBX_REVIEWED_CRASH_RECONCILE_TEST_H
#define BBX_REVIEWED_CRASH_RECONCILE_TEST_H
#if !defined(BBX_TEST_DURABLE_WORKER_RESTART) || \
    !defined(BBX_TEST_DURABLE_REPLAY) || \
    !defined(BBX_TEST_SIGNED_PEER_REQUIREMENT)
#error "Crash reconciliation requires a signed durable worker restart fixture."
#endif

static int bbx_test_armed_phase=0;
static char bbx_test_armed_nonce[37];
static char bbx_test_armed_txid[65];

static bool bbx_test_handle_crash_reconcile_control(
    xpc_connection_t peer,xpc_object_t request){
    const char *method=xpc_dictionary_get_string(request,"method");
    if(!method)return false;
    const bool arm=strcmp(method,"bbx_test_arm_receipt_crash")==0;
    const bool inspect=strcmp(method,"bbx_test_observe_receipt")==0;
    if(!arm&&!inspect)return false;

    const char *nonce=xpc_dictionary_get_string(request,"nonce");
    const char *txid=xpc_dictionary_get_string(request,"transactionId");
    const char *phase=arm?xpc_dictionary_get_string(request,"phase"):NULL;
    __block unsigned count=0;
    __block bool schema=true;
    xpc_dictionary_apply(request,^bool(const char *key,xpc_object_t value){
        count++;
        if(xpc_get_type(value)!=XPC_TYPE_STRING ||
           (strcmp(key,"method")!=0&&strcmp(key,"nonce")!=0&&
            strcmp(key,"transactionId")!=0&&
            !(arm&&strcmp(key,"phase")==0)))
            schema=false;
        return true;
    });
    const bool shape=schema&&count==(arm?4U:3U)&&
        bbx_reviewed_uuid4(nonce)&&bbx_reviewed_lowerhex(txid,64)&&
        (!arm || (phase&&(strcmp(phase,"before")==0||
                           strcmp(phase,"after")==0)));
    xpc_object_t reply=xpc_dictionary_create_reply(request);
    if(!reply)return true;
    const char *status="UNVERIFIABLE";
    if(shape&&arm){
        __block bool wasArmed=false;
        dispatch_sync(nonceQueue,^{
            if(bbx_test_armed_phase!=0)return;
            bbx_test_armed_phase=strcmp(phase,"before")==0?1:2;
            memcpy(bbx_test_armed_nonce,nonce,37);
            memcpy(bbx_test_armed_txid,txid,65);
            wasArmed=true;
        });
        status=wasArmed?"ARMED":"UNVERIFIABLE";
    }else if(shape&&inspect){
        const int directory=bbx_replay_directory();
        if(directory>=0){
            const BBXReplayObservation evidence=bbx_reviewed_replay_observe(
                directory,nonce,txid);
            close(directory);
            status=evidence==BBX_REPLAY_MATCHING_MARKER?"MATCHING_MARKER":
                   evidence==BBX_REPLAY_NO_MARKER?"NO_MARKER":"UNVERIFIABLE";
        }
    }
    xpc_dictionary_set_string(reply,"status",status);
    xpc_dictionary_set_uint64(reply,"workerPid",(uint64_t)getpid());
    xpc_dictionary_set_string(reply,"workerInstance",bbx_test_worker_instance);
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
    return true;
}
static void bbx_test_maybe_crash_receipt(
    const char *nonce,const char *transactionId,int boundary){
    if(bbx_test_armed_phase!=boundary ||
       strcmp(bbx_test_armed_nonce,nonce)!=0 ||
       strcmp(bbx_test_armed_txid,transactionId)!=0)return;
    /* Must run on the serialized receipt queue. No terminal XPC status
     * will be emitted. Faults cannot be reached on malformed payloads. */
    _exit(boundary==1?91:92);
}
#endif
