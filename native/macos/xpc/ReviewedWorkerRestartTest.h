/*
 * EXPERIMENTAL / TEST-MACRO-ONLY worker restart diagnostic.
 *
 * A correctly signed native host can ask the private XPC worker to report
 * its actual process instance and cooperatively exit. No PID/path/signal
 * supplied by an XPC caller controls termination. A valid one-field
 * diagnostic request is mandatory and the worker-side incoming OS
 * code-signing peer requirement is installed before message delivery.
 *
 * The host MUST independently establish the old PID exited, then compare
 * both actual PID and unpredictable per-process instance after reconnect.
 * No production XPC service or ordinary receipt build includes this file.
 */
#ifndef BBX_REVIEWED_WORKER_RESTART_TEST_H
#define BBX_REVIEWED_WORKER_RESTART_TEST_H

#if !defined(BBX_TEST_DURABLE_REPLAY) || !defined(BBX_TEST_SIGNED_PEER_REQUIREMENT)
#error "Test worker shutdown requires signed-peer-gated durable receipts."
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

static char bbx_test_worker_instance[33];

static void bbx_test_initialize_worker_instance(void){
    unsigned char randomBytes[16];
    const char alphabet[]="0123456789abcdef";
    arc4random_buf(randomBytes,sizeof(randomBytes));
    for(size_t i=0;i<sizeof(randomBytes);i++){
        bbx_test_worker_instance[2*i]=alphabet[randomBytes[i]>>4];
        bbx_test_worker_instance[2*i+1]=alphabet[randomBytes[i]&15];
    }
    bbx_test_worker_instance[32]='\0';
}

/* Return false for normal reviewed receipts so their ordinary strict
 * 12-field parser continues to enforce all authorization invariants. */
static bool bbx_test_handle_worker_lifecycle(
    xpc_connection_t peer,xpc_object_t request){
    const char *method=xpc_dictionary_get_string(request,"method");
    if(!method)return false;
    const bool info=strcmp(method,"bbx_test_worker_identity")==0;
    const bool stop=strcmp(method,"bbx_test_worker_exit")==0;
    if(!info&&!stop)return false;

    __block unsigned count=0;
    __block bool exact=true;
    xpc_dictionary_apply(request,^bool(const char *key,xpc_object_t value){
        count++;
        if(strcmp(key,"method")!=0||xpc_get_type(value)!=XPC_TYPE_STRING)
            exact=false;
        return true;
    });
    xpc_object_t reply=xpc_dictionary_create_reply(request);
    if(!reply)return true;
    if(!exact||count!=1||bbx_test_worker_instance[0]=='\0'){
        xpc_dictionary_set_string(reply,"status","BAD_REQUEST");
        xpc_connection_send_message(peer,reply);
        xpc_release(reply);
        return true;
    }

    xpc_dictionary_set_string(reply,"status",stop?"EXITING":"READY");
    xpc_dictionary_set_uint64(reply,"workerPid",(uint64_t)getpid());
    xpc_dictionary_set_string(reply,"workerInstance",bbx_test_worker_instance);
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
    if(stop){
        /*
         * Allow the asynchronous XPC reply to leave the worker, then end
         * THIS process only. Host must observe ESRCH before reconnecting.
         * This isn't a production kill command; compile gate is test only.
         */
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,300LL*NSEC_PER_MSEC),
            dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^{
                _exit(0);
            });
    }
    return true;
}
#endif
