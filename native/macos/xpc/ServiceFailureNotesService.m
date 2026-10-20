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
static void message(xpc_connection_t peer,xpc_object_t incoming) {
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
        /*
         * TEST-ONLY WORKER TERMINATION: force an abrupt service exit AFTER
         * the synthetic file was written and fsync'd, BEFORE the XPC reply.
         * Only the separate xpc-servicefault test worker contains this.
         * This simulates lost acknowledgement, not a kernel sandbox denial.
         */
        if(good && strncmp(name,"bbx-test-xpc-crash-",
                           sizeof("bbx-test-xpc-crash-")-1)==0)
            _exit(86);
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
    }else if(strcmp(op,"cleanup_test_note")==0) {
        xpc_dictionary_set_bool(response,"ok",unlinkat(dir,name,0)==0);
    }
close_dir:
    close(dir);
finish:
    xpc_connection_send_message(peer,response);
    xpc_release(response);
}
static void accept_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer,^(xpc_object_t event) {
        if(xpc_get_type(event)==XPC_TYPE_DICTIONARY)message(peer,event);
    });
    xpc_connection_resume(peer);
}
int main(void) {
    xpc_main(accept_peer);
    return 70;
}
