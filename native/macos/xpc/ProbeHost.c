/*
 * v0.8 EXPERIMENTAL: minimal macOS .app host to contact embedded private XPC.
 * The host is deliberately unsandboxed; the XPC worker must deny access.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>

static void fail(const char *message, int code) {
    fprintf(stderr,"XPC host: %s\n",message);
    fflush(stderr);
    exit(code);
}

int main(int argc,char **argv) {
    if(argc!=3 || argv[1][0]!='/' || strlen(argv[1])>4096)
        fail("expected synthetic absolute marker and port",64);
    char *end=NULL;
    long parsed=strtol(argv[2],&end,10);
    if(!end || *end!='\0' || parsed<1 || parsed>65535)
        fail("invalid loopback port",64);
#ifdef BBX_TEST_NOTES_ISOLATION
    const char *service="dev.agentblackbox.xpc-authority.worker";
#else
    const char *service="dev.agentblackbox.xpc-probe.worker";
#endif
    xpc_connection_t conn=xpc_connection_create(
        service,dispatch_get_main_queue());
    if(!conn)fail("could not create embedded XPC connection",70);
    xpc_connection_set_event_handler(conn,^(xpc_object_t event){
        if(xpc_get_type(event)==XPC_TYPE_ERROR)
            fail("XPC connection error or invalidation",71);
    });
    xpc_connection_resume(conn);

    xpc_object_t msg=xpc_dictionary_create(NULL,NULL,0);
    xpc_dictionary_set_string(msg,"method","probe");
    xpc_dictionary_set_string(msg,"hostFile",argv[1]);
    xpc_dictionary_set_int64(msg,"port",(int64_t)parsed);
    xpc_connection_send_message_with_reply(conn,msg,dispatch_get_main_queue(),^(xpc_object_t reply){
        if(xpc_get_type(reply)!=XPC_TYPE_DICTIONARY ||
           !xpc_dictionary_get_bool(reply,"valid"))
           fail("XPC service did not return a valid reply",72);
        /*
         * The XPC reply's valid flag has already been verified above.
         * In the notes isolation build forward it as a literal verified
         * acknowledgement so the strict JS gate can distinguish a valid
         * worker reply from missing/invalid output. Preserve the historical
         * generic XPC probe JSON format in the ordinary build.
         */
#ifdef BBX_TEST_NOTES_ISOLATION
        const char *verifiedPrefix="{\"valid\":true,";
#else
        const char *verifiedPrefix="{";
#endif
        printf("%s\"hostPID\":%ld,\"workerPID\":%" PRId64 ","
               "\"hostFileDenied\":%s,\"hostFileErrno\":%" PRId64 ","
               "\"networkDenied\":%s,\"networkErrorNumber\":%" PRId64 ","
               "\"temporaryWriteAllowed\":%s,\"temporaryWriteErrno\":%" PRId64 "}\n",
               verifiedPrefix,(long)getpid(),xpc_dictionary_get_int64(reply,"workerPID"),
               xpc_dictionary_get_bool(reply,"hostFileDenied")?"true":"false",
               xpc_dictionary_get_int64(reply,"hostFileErrno"),
               xpc_dictionary_get_bool(reply,"networkDenied")?"true":"false",
               xpc_dictionary_get_int64(reply,"networkErrorNumber"),
               xpc_dictionary_get_bool(reply,"temporaryWriteAllowed")?"true":"false",
               xpc_dictionary_get_int64(reply,"temporaryWriteErrno"));
        fflush(stdout);
        exit(0);
    });
    xpc_release(msg);

    dispatch_source_t timeout=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
    dispatch_source_set_timer(timeout,dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC),
        DISPATCH_TIME_FOREVER,0);
    dispatch_source_set_event_handler(timeout,^{fail("XPC response timed out",73);});
    dispatch_resume(timeout);
    dispatch_main();
}
