/*
 * v0.8 experimental Node->native-host->XPC durable test bridge.
 *
 * Frame: "READ|WRITE|REMOVE NAME BYTE_LENGTH\n" followed by BYTE_LENGTH
 * content bytes (WRITE only). Reply: "OK|ERR BYTE_LENGTH\n" followed by
 * raw bytes (READ only). Never puts note contents in command arguments.
 *
 * Narrow synthetic-only operation set: no paths, shell, network, or gateway
 * keys. A blocked synchronous XPC call must be killed by its Node supervisor.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>

static bool test_name(const char *name) {
    size_t n=name?strnlen(name,80):0;
    if(n<14||n>64||strncmp(name,"bbx-test-",9)!=0||
       strcmp(name+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        unsigned char c=(unsigned char)name[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
static bool ascii_note(const char *data,size_t size) {
    for(size_t i=0;i<size;i++){
        unsigned char c=(unsigned char)data[i];
        if(!((c>=32&&c<=126)||c=='\n'||c=='\t'))return false;
    }
    return true;
}
static void response(bool ok,const char *data,size_t n) {
    if(!ok){fputs("ERR 0\n",stdout);fflush(stdout);return;}
    printf("OK %zu\n",n);
    if(n && fwrite(data,1,n,stdout)!=n)exit(76);
    fflush(stdout);
}
int main(void){
    xpc_connection_t connection=xpc_connection_create("dev.agentblackbox.xpc-authority.worker",
                                                       dispatch_get_global_queue(QOS_CLASS_DEFAULT,0));
    if(!connection)return 70;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);
    char header[160];
    while(fgets(header,sizeof(header),stdin)){
        char op[8]={0},name[80]={0},junk[2]={0};
        long declared=-1;
        if(!strchr(header,'\n')||
           sscanf(header,"%7s %79s %ld %1s",op,name,&declared,junk)!=3||
           declared<0||declared>2000) {
            fprintf(stderr,"Malformed fixed bridge frame.\n");
            xpc_connection_cancel(connection);
            xpc_release(connection);
            return 65;
        }
        const bool writeOp=strcmp(op,"WRITE")==0;
        const bool readOp=strcmp(op,"READ")==0;
        const bool removeOp=strcmp(op,"REMOVE")==0;
        const bool rootOp=strcmp(op,"ROOT")==0;
        if((!writeOp&&!readOp&&!removeOp&&!rootOp)||
           (writeOp && declared<1) || (!writeOp&&declared!=0)) {
            fprintf(stderr,"Unsupported fixed bridge command.\n");
            xpc_connection_cancel(connection);
            xpc_release(connection);
            return 65;
        }
        char content[2001]={0};
        if(writeOp && fread(content,1,(size_t)declared,stdin)!=(size_t)declared) {
            fprintf(stderr,"Truncated fixed bridge frame.\n");
            xpc_connection_cancel(connection);
            xpc_release(connection);
            return 66;
        }
        if((rootOp&&(strcmp(name,"-")!=0||declared!=0)) ||
           (!rootOp&&!test_name(name)) ||
           (writeOp&&!ascii_note(content,(size_t)declared))){
            response(false,NULL,0);
            continue;
        }
        /*
         * EXPLICIT synthetic-only fault injection. Separate test build only:
         * never compile this C source into the ordinary native host.
         * Node forwards this environment flag only in the Phase-3C harness.
         */
        const bool faultMode=getenv("BLACKBOX_XPC_TEST_FAULT") &&
            strcmp(getenv("BLACKBOX_XPC_TEST_FAULT"),"1")==0;
        if(faultMode && writeOp &&
           strncmp(name,"bbx-test-fault-hang-",20)==0) {
            for(;;)pause(); // Node supervisor must kill the hung host.
        }
        xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_string(request,"method",rootOp?"workspace_info":
                                  writeOp?"write_note":readOp?"read_note":
                                  "cleanup_test_note");
        xpc_dictionary_set_string(request,"path",name);
        if(writeOp)xpc_dictionary_set_string(request,"content",content);
        /*
         * Apple's synchronous API can block indefinitely. This experimental
         * host relies on Node's external kill deadline. A timed-out write
         * is an UNKNOWN outcome, not a safe rollback.
         */
        xpc_object_t reply=xpc_connection_send_message_with_reply_sync(connection,request);
        xpc_release(request);
        if(faultMode && writeOp &&
           strncmp(name,"bbx-test-fault-crash-",21)==0 &&
           reply && xpc_get_type(reply)==XPC_TYPE_DICTIONARY &&
           xpc_dictionary_get_bool(reply,"ok")) {
            /* XPC confirms the create completed, but Node sees SIGKILL. */
            raise(SIGKILL);
        }
        if(!reply || xpc_get_type(reply)!=XPC_TYPE_DICTIONARY ||
           !xpc_dictionary_get_bool(reply,"ok")){
            response(false,NULL,0);
        } else if(rootOp) {
            const char *reported=xpc_dictionary_get_string(reply,"workspaceRoot");
            size_t n=reported?strnlen(reported,2001):2001;
            if(n==0||n>2000||!reported||strchr(reported,'\n'))
                response(false,NULL,0);
            else response(true,reported,n);
        } else if(readOp) {
            const char *returned=xpc_dictionary_get_string(reply,"content");
            size_t size=returned?strnlen(returned,2001):2001;
            if(size>2000||!returned)response(false,NULL,0);
            else response(true,returned,size);
        } else response(true,NULL,0);
        if(reply)xpc_release(reply);
    }
    xpc_connection_cancel(connection);
    xpc_release(connection);
    return ferror(stdin)?74:0;
}
