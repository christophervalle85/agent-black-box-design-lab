/*
 * TEST ONLY: controller-owned durable nonce reservation for a previously
 * validated synthetic review. This is distinct from the sandboxed XPC
 * worker's receipt ledger and cannot prove Node's HMAC audit legitimacy.
 *
 * Uses only a fixed home-relative path, not one supplied over stdin or argv.
 * No symlinks and no permissive private subfolders. Atomic O_EXCL creation
 * and fsync both marker and containing directory before issuing signature.
 * A failed/ambiguous reservation burns the nonce; never remove markers.
 * Same-user deletion/rollback remains possible. Not production ACL.
 */
#ifndef BBX_TEST_CONTROLLER_SIGNING_RESERVATION_H
#define BBX_TEST_CONTROLLER_SIGNING_RESERVATION_H

#include "ReviewedDurableReplay.h"
#include <Foundation/Foundation.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static inline int bbx_test_open_signing_subfolder(int parent,
    const char *name,bool privateMode){
    if(parent<0)return -1;
    if(mkdirat(parent,name,privateMode?0700:0700)!=0&&errno!=EEXIST)
        return -1;
    const int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    struct stat st={0};
    if(fstat(fd,&st)!=0||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||
       (privateMode&&(st.st_mode&077)!=0)){
        close(fd);
        return -1;
    }
    if(fsync(parent)!=0){close(fd);return -1;}
    return fd;
}
static inline int bbx_test_controller_signing_directory(void){
    @autoreleasepool {
        const char *home=[NSHomeDirectory() fileSystemRepresentation];
        if(!home||home[0]!='/'||strnlen(home,4096)>=4096)return -1;
        const int homefd=open(home,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(homefd<0)return -1;
        const int library=bbx_test_open_signing_subfolder(
            homefd,"Library",false);
        close(homefd);
        if(library<0)return -1;
        const int support=bbx_test_open_signing_subfolder(
            library,"Application Support",false);
        close(library);
        if(support<0)return -1;
        const int root=bbx_test_open_signing_subfolder(
            support,"AgentBlackBox",true);
        close(support);
        if(root<0)return -1;
        const int destination=bbx_test_open_signing_subfolder(
            root,"ControllerSigning",true);
        close(root);
        return destination;
    }
}
#endif
