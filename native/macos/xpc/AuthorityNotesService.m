/*
 * EXPERIMENTAL v0.8: narrowly-scoped, sandboxed XPC note operations.
 * Operates on synthetic "bbx-test-*.txt" files within its own sandbox
 * Documents directory. Separate test service ID: no production data.
 * NOT production storage and NOT reachable through the Node MCP gateway.
 */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#ifdef BBX_TEST_NOTES_ISOLATION
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#if defined(BBX_TEST_INBOUND_PEER_REQUIREMENT) || defined(BBX_NATIVE_OPERATOR_TRANSFER) || defined(BBX_NATIVE_REQUIRED_MCP)
#include "PeerRequirementGate.h"
#endif
#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT
#if defined(BBX_TEST_NOTES_ISOLATION)
#error "Inbound peer requirement and OS-isolation diagnostics must be separate."
#endif
#endif
#import <Foundation/Foundation.h>

static bool allowed_name(const char *name) {
    if (!name) return false;
    size_t n=strnlen(name,80);
    const size_t prefix=sizeof("bbx-test-")-1;
    if(n<=prefix+4||n>64||strncmp(name,"bbx-test-",prefix)!=0||
       strcmp(name+n-4,".txt")!=0) return false;
    for(size_t i=prefix;i<n-4;i++) {
        unsigned char c=(unsigned char)name[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
/*
 * Ask Foundation for the sandbox-managed Documents directory; do not accept
 * a root path supplied over IPC or hard-code the Node demo workspace.
 * A conservative container-location assertion fails closed outside the
 * expected macOS App Sandbox app-data hierarchy. This may require
 * adjustment for other officially supported macOS layouts.
 */
static int notes_fd(void) {
    @autoreleasepool {
        NSError *error=nil;
        NSURL *documents=[[NSFileManager defaultManager]
            URLForDirectory:NSDocumentDirectory
            inDomain:NSUserDomainMask
            appropriateForURL:nil
            create:YES
            error:&error];
        if(!documents)return -1;
        const char *path=[documents fileSystemRepresentation];
        if(!path || !strstr(path,"/Library/Containers/") ||
           !strstr(path,"/Data/Documents"))return -1;
        int parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(parent<0)return -1;
        if(mkdirat(parent,"AgentBlackBoxScratchNotes",0700)<0 && errno!=EEXIST){
            close(parent);
            return -1;
        }
        int dir=openat(parent,"AgentBlackBoxScratchNotes",
                       O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(parent);
        if(dir<0)return -1;
        struct stat st;
        if(fstat(dir,&st)!=0 || !S_ISDIR(st.st_mode) ||
           (st.st_mode & 077)!=0 || st.st_uid!=geteuid()){
            close(dir);
            return -1;
        }
        return dir;
    }
}

#ifdef BBX_TEST_NOTES_ISOLATION
/*
 * BOUNDED, OPT-IN TEST INSTRUMENTATION; absent from ordinary notes builds.
 * Probe the ACTUAL AuthorityNotesService source under its own App Sandbox.
 * Input is a synthetic file created by the host and a host-owned listening
 * loopback port. Probe does not expose arbitrary file reads or data bytes.
 * Any probe command must be compiled out of production worker binaries.
 */
static void isolation_probe(xpc_connection_t peer,xpc_object_t incoming) {
    xpc_object_t reply=xpc_dictionary_create_reply(incoming);
    if(!reply)return;
    xpc_dictionary_set_bool(reply,"valid",false);
    const char *marker=xpc_dictionary_get_string(incoming,"hostFile");
    int64_t requestedPort=xpc_dictionary_get_int64(incoming,"port");
    if(!marker || marker[0]!='/' || strnlen(marker,4097)>4096 ||
       requestedPort<1 || requestedPort>65535)goto finish;

    int fd=open(marker,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    int fileError=fd<0?errno:0;
    if(fd>=0)close(fd);
    bool fileDenied=fd<0&&(fileError==EPERM||fileError==EACCES);

    int sock=socket(AF_INET,SOCK_STREAM,0);
    int networkError=sock<0?errno:0;
    bool networkDenied=false;
    if(sock>=0){
        struct sockaddr_in addr={0};
        addr.sin_len=sizeof(addr);
        addr.sin_family=AF_INET;
        addr.sin_port=htons((uint16_t)requestedPort);
        addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        int connected=connect(sock,(struct sockaddr *)&addr,sizeof(addr));
        if(connected<0)networkError=errno;
        networkDenied=connected<0&&
            (networkError==EPERM||networkError==EACCES);
        close(sock);
    }else networkDenied=networkError==EPERM||networkError==EACCES;

    bool privateWriteAllowed=false;
    int privateWriteError=0;
    int dir=notes_fd(); /* SAME protected Documents root as real note ops. */
    if(dir<0)privateWriteError=errno?errno:EACCES;
    else {
        char name[64];
        int n=snprintf(name,sizeof(name),"bbx-test-isolation-%ld.txt",
                       (long)getpid());
        if(n<=0 || n>=(int)sizeof(name))privateWriteError=EINVAL;
        else {
            int out=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|
                            O_NOFOLLOW|O_CLOEXEC,0600);
            if(out<0)privateWriteError=errno;
            else {
                const char data[]="synthetic-isolation-test";
                ssize_t written=write(out,data,sizeof(data)-1);
                int writeError=written==(ssize_t)(sizeof(data)-1)?0:errno;
                if(writeError==0 && fsync(out)<0)writeError=errno;
                if(close(out)<0 && writeError==0)writeError=errno;
                int removed=unlinkat(dir,name,0);
                if(removed<0 && writeError==0)writeError=errno;
                privateWriteAllowed=writeError==0&&removed==0;
                privateWriteError=writeError;
            }
        }
        close(dir);
    }
    xpc_dictionary_set_bool(reply,"hostFileDenied",fileDenied);
    xpc_dictionary_set_int64(reply,"hostFileErrno",fileError);
    xpc_dictionary_set_bool(reply,"networkDenied",networkDenied);
    xpc_dictionary_set_int64(reply,"networkErrorNumber",networkError);
    // Retain existing fixed probe response schema for the independent
    // verifier; this positive check writes into worker's private Documents
    // scratch directory, *not* the OS temporary directory.
    xpc_dictionary_set_bool(reply,"temporaryWriteAllowed",privateWriteAllowed);
    xpc_dictionary_set_int64(reply,"temporaryWriteErrno",privateWriteError);
    xpc_dictionary_set_int64(reply,"workerPID",(int64_t)getpid());
    xpc_dictionary_set_bool(reply,"valid",true);
finish:
    xpc_connection_send_message(peer,reply);
    xpc_release(reply);
}
#endif


#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT
/*
 * Test-only, content-free proof that the native *worker* installed Apple's
 * same-team requirement and is running. Both markers live exclusively
 * in this worker's existing sandbox-owned Documents scratch directory.
 * No diagnostic method is added to the production worker.
 */
static bool bbx_inbound_peer_marker(const char *name) {
    int dir=notes_fd();
    if(dir<0)return false;
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){close(dir);return false;}
    char data[48];
    int count=snprintf(data,sizeof(data),"%ld\n",(long)getpid());
    bool success=count>0 && count<(int)sizeof(data) &&
                 write(fd,data,(size_t)count)==count && fsync(fd)==0;
    if(close(fd)<0)success=false;
    if(!success)unlinkat(dir,name,0);
    close(dir);
    return success;
}
#endif

static void message(xpc_connection_t peer,xpc_object_t incoming) {
#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT
    /* If the OS ever delivers this unauthorized message, leave durable
     * evidence and never execute a normal notes operation. */
    (void)bbx_inbound_peer_marker("bbx-test-inbound-delivered.txt");
    xpc_connection_cancel(peer);
    return;
#endif
#ifdef BBX_TEST_NOTES_ISOLATION
    const char *method=xpc_dictionary_get_string(incoming,"method");
    if(method && strcmp(method,"probe")==0){
        isolation_probe(peer,incoming);
        return;
    }
#endif
    xpc_object_t response=xpc_dictionary_create_reply(incoming);
    if(!response)return;
    xpc_dictionary_set_bool(response,"ok",false);
    xpc_dictionary_set_int64(response,"workerPID",(int64_t)getpid());
    const char *op=xpc_dictionary_get_string(incoming,"method");
    const char *name=xpc_dictionary_get_string(incoming,"path");
    if(!op)goto finish;
    if(strcmp(op,"workspace_info")==0) {
        /* Only directory identity, not arbitrary filesystem enumeration. */
        int root=notes_fd();
        if(root<0)goto finish;
        char canonical[PATH_MAX]={0};
        int status=fcntl(root,F_GETPATH,canonical);
        close(root);
        if(status<0 || !strstr(canonical,"/Library/Containers/") ||
           !strstr(canonical,"/Data/Documents/AgentBlackBoxScratchNotes"))
            goto finish;
        xpc_dictionary_set_string(response,"workspaceRoot",canonical);
        xpc_dictionary_set_bool(response,"ok",true);
        goto finish;
    }
    if(!allowed_name(name))goto finish;
    int dir=notes_fd();
    if(dir<0)goto finish;
    if(strcmp(op,"write_note")==0) {
        const char *data=xpc_dictionary_get_string(incoming,"content");
        if(!data)goto close_dir;
        size_t length=strnlen(data,2001);
        if(length==0||length>2000)goto close_dir;
        int file=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(file<0)goto close_dir;
        ssize_t n=write(file,data,length);
        bool good=n==(ssize_t)length && fsync(file)==0;
        if(close(file)!=0)good=false;
        if(!good)unlinkat(dir,name,0);
        xpc_dictionary_set_bool(response,"ok",good);
    }else if(strcmp(op,"read_note")==0) {
        int file=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(file<0)goto close_dir;
        struct stat info;
        if(fstat(file,&info)==0 && S_ISREG(info.st_mode) && info.st_size>=0 &&
           info.st_size<=2000) {
            char data[2002]={0};
            ssize_t count=read(file,data,2001);
            if(count>=0 && count<=2000 && memchr(data,'\0',(size_t)count)==NULL) {
                data[count]='\0';
                xpc_dictionary_set_string(response,"content",data);
                xpc_dictionary_set_bool(response,"ok",true);
            }
        }
        close(file);
#ifndef BBX_NATIVE_REQUIRED_MCP
    }else if(strcmp(op,"cleanup_test_note")==0) {
        xpc_dictionary_set_bool(response,"ok",unlinkat(dir,name,0)==0);
#endif
    }
close_dir:
    close(dir);
finish:
    xpc_connection_send_message(peer,response);
    xpc_release(response);
}
static void accept_peer(xpc_connection_t peer) {
#if defined(BBX_NATIVE_OPERATOR_TRANSFER) || defined(BBX_NATIVE_REQUIRED_MCP)
    /* Native operator and required MCP builds. The OS must enforce matching
       Team ID AND the exact signed host identifier before handler delivery.
       Never fall back to UID/PID or an unauthenticated connection. */
    if(bbx_install_same_team_peer_requirement(peer,
       "dev.agentblackbox.xpc-authority.host")!=0){
        xpc_connection_cancel(peer);
        return;
    }
#endif
#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT
    /*
     * Install exactly one OS-enforced signature requirement on each
     * incoming connection BEFORE resume; never fall back to UID/PID.
     * The test host is ad-hoc signed and must NOT qualify as the worker's
     * same-Team-ID peer. No ordinary release builds contain this fixture.
     */
    int peerGate=bbx_install_same_team_peer_requirement(
        peer,"dev.agentblackbox.xpc-inbound-restricted.host");
    if(peerGate!=0){
        xpc_connection_cancel(peer);
        return;
    }
    /* TEST ONLY: hold the worker active while the native harness checks
     * peer rejection. This does not change authorization or release builds. */
    xpc_transaction_begin();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,6*NSEC_PER_SEC),
        dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^{
            xpc_transaction_end();
        });
    if(!bbx_inbound_peer_marker("bbx-test-inbound-armed.txt")){
        xpc_connection_cancel(peer);
        return;
    }
#endif
    xpc_connection_set_event_handler(peer,^(xpc_object_t event) {
        if(xpc_get_type(event)==XPC_TYPE_DICTIONARY)message(peer,event);
    });
    xpc_connection_resume(peer);
}
int main(void) {
    xpc_main(accept_peer);
    return 70;
}
