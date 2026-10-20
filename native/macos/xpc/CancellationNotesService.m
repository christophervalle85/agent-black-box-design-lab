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
#include <stdatomic.h>
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
/*
 * EXPERIMENTAL IN-FLIGHT CANCELLATION ONLY:
 * A write named bbx-test-cancel-during-*.txt runs on a background queue,
 * allowing the XPC peer invalidation event to be processed independently.
 * The service creates a private, content-free synthetic marker inside its
 * own Documents scratch directory only after it begins executing the work.
 * This is NOT a production transaction or cancellation protocol.
 */
static bool delayed_name(const char *name) {
    return allowed_name(name) &&
      strncmp(name,"bbx-test-cancel-during-",
              sizeof("bbx-test-cancel-during-")-1)==0;
}
static void delayed_message(xpc_connection_t peer,xpc_object_t incoming,
                            atomic_bool *peer_closed) {
    @autoreleasepool {
        const char *name=xpc_dictionary_get_string(incoming,"path");
        char marker[80]={0};
        int dir=-1;
        if(!name || !delayed_name(name) ||
           snprintf(marker,sizeof(marker),"bbx-test-cancel-running-%s",
                    name+sizeof("bbx-test-cancel-during-")-1) >= (int)sizeof(marker))
            goto end;
        dir=notes_fd();
        if(dir<0)goto end;
        int fd=openat(dir,marker,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)goto end;
        const char started[]="worker-running\n";
        bool marked=write(fd,started,sizeof(started)-1)==(ssize_t)sizeof(started)-1
                    && fsync(fd)==0;
        if(close(fd)!=0)marked=false;
        if(!marked){unlinkat(dir,marker,0);goto end;}
        /* Bounded 4-second synthetic execution window, never arbitrary work. */
        for(unsigned i=0;i<160 && !atomic_load(peer_closed);i++)
            usleep(25000);
        /* A kill of the host closes its XPC peer. This test worker detects
         * invalidation while a separate queue is executing. If the write
         * races invalidation at this check, the gateway still audits UNKNOWN.
         */
        if(!atomic_load(peer_closed))message(peer,incoming);
        unlinkat(dir,marker,0);
end:
        if(dir>=0)close(dir);
        xpc_release(incoming);
        xpc_release(peer);
    }
}
static void accept_peer(xpc_connection_t peer) {
    // Tiny test-only per-connection cancellation latch. The disposable XPC
    // worker is short-lived; never copy this allocation model to production.
    atomic_bool *peer_closed=calloc(1,sizeof(*peer_closed));
    if(!peer_closed){xpc_connection_cancel(peer);return;}
    atomic_init(peer_closed,false);
    xpc_connection_set_event_handler(peer,^(xpc_object_t event) {
        if(xpc_get_type(event)==XPC_TYPE_DICTIONARY) {
            const char *method=xpc_dictionary_get_string(event,"method");
            const char *name=xpc_dictionary_get_string(event,"path");
            if(method && strcmp(method,"write_note")==0 &&
               delayed_name(name)) {
                xpc_retain(peer);
                xpc_retain(event);
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT,0), ^{
                    delayed_message(peer,event,peer_closed);
                });
            }else message(peer,event);
        }else if(event==XPC_ERROR_CONNECTION_INVALID) {
            atomic_store(peer_closed,true);
        }
    });
    xpc_connection_resume(peer);
}
int main(void) {
    xpc_main(accept_peer);
    return 70;
}
