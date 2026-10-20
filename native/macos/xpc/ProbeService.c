/*
 * v0.8 EXPERIMENTAL: launchd-managed XPC feasibility probe.
 * NOT the production MCP notes worker.
 * Only accepts one fixed "probe" request; no arbitrary tool execution.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static void respond(xpc_connection_t peer, xpc_object_t message) {
    xpc_object_t reply=xpc_dictionary_create_reply(message);
    if(!reply)return;
    const char *method=xpc_dictionary_get_string(message,"method");
    const char *marker=xpc_dictionary_get_string(message,"hostFile");
    int64_t port=xpc_dictionary_get_int64(message,"port");
    if(!method || strcmp(method,"probe")!=0 || !marker || marker[0]!='/' ||
       strlen(marker)>4096 || port<1 || port>65535){
        xpc_dictionary_set_bool(reply,"valid",false);
        xpc_connection_send_message(peer,reply);
        xpc_release(reply);
        return;
    }
    int fd=open(marker,O_RDONLY);
    int fileError=fd<0?errno:0;
    if(fd>=0)close(fd);
    const bool fileDenied=fd<0&&(fileError==EPERM||fileError==EACCES);

    int sock=socket(AF_INET,SOCK_STREAM,0);
    int netError=0;
    bool netDenied=false;
    if(sock<0) netError=errno;
    else {
        struct sockaddr_in address={0};
        address.sin_len=sizeof(address);
        address.sin_family=AF_INET;
        address.sin_port=htons((uint16_t)port);
        address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        int ok=connect(sock,(struct sockaddr *)&address,sizeof(address));
        if(ok<0)netError=errno;
        netDenied=ok<0&&(netError==EPERM||netError==EACCES);
        close(sock);
    }

    bool tempWrite=false;
    int tempError=0;
    const char *tmp=getenv("TMPDIR");
    if(tmp && strlen(tmp)<PATH_MAX-32){
        char templatePath[PATH_MAX];
        int n=snprintf(templatePath,sizeof(templatePath),"%s%sblackbox-xpc-XXXXXX",
            tmp,strlen(tmp)>0&&tmp[strlen(tmp)-1]=='/'?"":"/");
        if(n>0 && n<(int)sizeof(templatePath)){
            int out=mkstemp(templatePath);
            if(out<0)tempError=errno;
            else {
                ssize_t written=write(out,"ok",2);
                int writeError=written==2?0:errno;
                close(out);
                int unlinkResult=unlink(templatePath);
                tempWrite=written==2&&unlinkResult==0;
                tempError=written!=2?writeError:(unlinkResult<0?errno:0);
            }
        }
    }
    xpc_dictionary_set_bool(reply,"valid",true);
    xpc_dictionary_set_bool(reply,"hostFileDenied",fileDenied);
    xpc_dictionary_set_int64(reply,"hostFileErrno",fileError);
    xpc_dictionary_set_bool(reply,"networkDenied",netDenied);
    xpc_dictionary_set_int64(reply,"networkErrorNumber",netError);
    xpc_dictionary_set_bool(reply,"temporaryWriteAllowed",tempWrite);
    xpc_dictionary_set_int64(reply,"temporaryWriteErrno",tempError);
    xpc_dictionary_set_int64(reply,"workerPID",(int64_t)getpid());
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
}

/*
 * Apple's xpc_main() takes xpc_connection_handler_t: a C function pointer.
 * xpc_connection_set_event_handler() separately accepts an XPC block.
 */
static void accept_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        if(xpc_get_type(event)==XPC_TYPE_DICTIONARY)respond(peer,event);
    });
    xpc_connection_resume(peer);
}

int main(void) {
    xpc_main(accept_peer);
    return 70; // xpc_main does not normally return.
}
