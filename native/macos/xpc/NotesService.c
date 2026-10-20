/*
 * EXPERIMENTAL v0.8: narrowly-scoped, sandboxed XPC note operations.
 * Operates on synthetic "bbx-test-*.txt" files inside the service TMPDIR.
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
static int scratch_fd(void) {
    const char *tmp=getenv("TMPDIR");
    if(!tmp||tmp[0]!='/'||strnlen(tmp,PATH_MAX)>=PATH_MAX)return -1;
    return open(tmp,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
}
static void message(xpc_connection_t peer,xpc_object_t incoming) {
    xpc_object_t response=xpc_dictionary_create_reply(incoming);
    if(!response)return;
    xpc_dictionary_set_bool(response,"ok",false);
    xpc_dictionary_set_int64(response,"workerPID",(int64_t)getpid());
    const char *op=xpc_dictionary_get_string(incoming,"method");
    const char *name=xpc_dictionary_get_string(incoming,"path");
    if(!op||!allowed_name(name))goto finish;
    int dir=scratch_fd();
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
