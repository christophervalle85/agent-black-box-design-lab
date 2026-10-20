/*
 * EXPERIMENTAL XPC note-operation roundtrip host. Fixed synthetic content,
 * no arbitrary user arguments, and does not print stored note text.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

static xpc_connection_t connection;
static char filename[80];
static const char *testContent="Agent Black Box native XPC note test.";
static bool wrote=false,readMatched=false,invalidRejected=false,cleaned=false;
static int64_t workerPID=0;

static void fail(const char *msg,int code) {
    fprintf(stderr,"XPC notes host: %s\n",msg);
    fflush(stderr);
    exit(code);
}
static xpc_object_t request(const char *method,const char *path,const char *content) {
    xpc_object_t msg=xpc_dictionary_create(NULL,NULL,0);
    xpc_dictionary_set_string(msg,"method",method);
    xpc_dictionary_set_string(msg,"path",path);
    if(content)xpc_dictionary_set_string(msg,"content",content);
    return msg;
}
static bool valid_reply(xpc_object_t result) {
    if(xpc_get_type(result)!=XPC_TYPE_DICTIONARY)fail("invalid XPC response",72);
    int64_t pid=xpc_dictionary_get_int64(result,"workerPID");
    if(pid<=0)fail("missing native worker identity",72);
    if(workerPID && pid!=workerPID)fail("worker identity changed mid-request",73);
    workerPID=pid;
    return xpc_dictionary_get_bool(result,"ok");
}
static void send_cleanup(void);
static void send_invalid(void);
static void send_read(void);

static void send_write(void) {
    xpc_object_t msg=request("write_note",filename,testContent);
    xpc_connection_send_message_with_reply(connection,msg,dispatch_get_main_queue(),
        ^(xpc_object_t result) {
            wrote=valid_reply(result);
            if(!wrote)fail("native note creation denied",74);
            send_read();
        });
    xpc_release(msg);
}
static void send_read(void) {
    xpc_object_t msg=request("read_note",filename,NULL);
    xpc_connection_send_message_with_reply(connection,msg,dispatch_get_main_queue(),
        ^(xpc_object_t result) {
            if(valid_reply(result)) {
                const char *contents=xpc_dictionary_get_string(result,"content");
                readMatched=contents && strcmp(contents,testContent)==0;
            }
            if(!readMatched)fail("native note read mismatch",75);
            send_invalid();
        });
    xpc_release(msg);
}
static void send_invalid(void) {
    xpc_object_t msg=request("read_note","../../.ssh/id_ed25519",NULL);
    xpc_connection_send_message_with_reply(connection,msg,dispatch_get_main_queue(),
        ^(xpc_object_t result) {
            invalidRejected=!valid_reply(result);
            if(!invalidRejected)fail("native note path traversal accepted",76);
            send_cleanup();
        });
    xpc_release(msg);
}
static void send_cleanup(void) {
    xpc_object_t msg=request("cleanup_test_note",filename,NULL);
    xpc_connection_send_message_with_reply(connection,msg,dispatch_get_main_queue(),
        ^(xpc_object_t result) {
            cleaned=valid_reply(result);
            if(!cleaned)fail("synthetic note cleanup failed",77);
            printf("{\"hostPID\":%ld,\"workerPID\":%" PRId64 ","
                   "\"writeAllowed\":%s,\"readMatched\":%s,"
                   "\"traversalRejected\":%s,\"cleanupAllowed\":%s}\n",
                   (long)getpid(),workerPID,wrote?"true":"false",
                   readMatched?"true":"false",invalidRejected?"true":"false",
                   cleaned?"true":"false");
            fflush(stdout);
            exit(0);
        });
    xpc_release(msg);
}
int main(void) {
    int n=snprintf(filename,sizeof(filename),"bbx-test-%ld-%ld.txt",
                   (long)getpid(),(long)time(NULL));
    if(n<=0 || n>=(int)sizeof(filename))fail("test filename too long",64);
    connection=xpc_connection_create("dev.agentblackbox.xpc-notes.worker",
                                     dispatch_get_main_queue());
    if(!connection)fail("no private notes service",70);
    xpc_connection_set_event_handler(connection,^(xpc_object_t event){
        if(xpc_get_type(event)==XPC_TYPE_ERROR)
            fail("native notes XPC connection invalidated",71);
    });
    xpc_connection_resume(connection);
    dispatch_source_t deadline=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,
                                                       dispatch_get_main_queue());
    dispatch_source_set_timer(deadline,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),
                               DISPATCH_TIME_FOREVER,0);
    dispatch_source_set_event_handler(deadline,^{fail("XPC notes deadline exceeded",78);});
    dispatch_resume(deadline);
    send_write();
    dispatch_main();
}
