/*
 * v0.8 Phase 6 diagnostic: Native macOS file-picker -> bounded fd snapshot.
 *
 * This reads ONLY the generated bbx-test-snapshot.txt, in a throwaway folder.
 * No production documents, no MCP/XPC integration, no file contents/path
 * printed, no persistent approval or OS sandbox production claim.
 *
 * A pre-panel O_NOFOLLOW descriptor pins the generated fixture. After
 * NSOpenPanel returns, open the selected leaf O_NOFOLLOW, fstat both FDs,
 * require matching device/inode and strict regular-file limits, then hash
 * exactly the bytes read from the opened selected FD (not a re-opened path).
 */
#define __STDC_WANT_LIB_EXT1__ 1
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BBX_SNAPSHOT_MAX 2000
/* Apple's documented memset_s prevents dead-store elimination. If a
 * supposedly-valid wipe ever fails, never continue to emit success. */
static void secure_wipe(void *buffer,size_t count){
    if(memset_s(buffer,count,0,count)!=0)abort();
}
static int deny(const char *label,int code){puts(label);fflush(stdout);return code;}
static bool validFd(int fd,struct stat *out){
    if(fd<0 || fstat(fd,out)!=0)return false;
    return S_ISREG(out->st_mode) && out->st_uid==geteuid() &&
           out->st_nlink==1 && out->st_size>0 &&
           out->st_size<=BBX_SNAPSHOT_MAX;
}
static bool exactSameFile(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
           a->st_size==b->st_size;
}
int main(int argc,const char **argv){
    @autoreleasepool{
        if(argc!=2 || !argv[1] || argv[1][0]!='/' ||
           strnlen(argv[1],4097)>4096)
            return deny("BBX_SNAPSHOT_INVALID_FIXTURE",90);
        NSString *fixture=[NSString stringWithUTF8String:argv[1]];
        if(!fixture || ![fixture.lastPathComponent
                          isEqualToString:@"bbx-test-snapshot.txt"])
            return deny("BBX_SNAPSHOT_INVALID_FIXTURE",90);
        int pinned=open(argv[1],O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        struct stat expected;
        if(!validFd(pinned,&expected)){
            if(pinned>=0)close(pinned);
            return deny("BBX_SNAPSHOT_INVALID_FIXTURE",90);
        }
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSOpenPanel *panel=[NSOpenPanel openPanel];
        panel.title=@"Agent Black Box — synthetic native byte snapshot";
        panel.message=@"Select ONLY bbx-test-snapshot.txt. The test reads just this generated file.";
        panel.prompt=@"Select Synthetic File";
        panel.canChooseFiles=YES;
        panel.canChooseDirectories=NO;
        panel.allowsMultipleSelection=NO;
        panel.resolvesAliases=NO;
        panel.directoryURL=[NSURL fileURLWithPath:
            fixture.stringByDeletingLastPathComponent isDirectory:YES];
        [NSApp activateIgnoringOtherApps:YES];
        NSModalResponse answer=[panel runModal];
        if(answer==NSModalResponseCancel){
            close(pinned);
            return deny("BBX_SNAPSHOT_USER_CANCELLED",83);
        }
        if(answer!=NSModalResponseOK || panel.URLs.count!=1 ||
           !panel.URLs.firstObject.isFileURL){
            close(pinned);
            return deny("BBX_SNAPSHOT_INVALID_SELECTION",87);
        }
        NSString *selected=panel.URLs.firstObject.path;
        if(![selected.lastPathComponent
               isEqualToString:@"bbx-test-snapshot.txt"]){
            close(pinned);
            return deny("BBX_SNAPSHOT_WRONG_FILE",87);
        }
        int fd=open(selected.fileSystemRepresentation,
                    O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        struct stat before;
        if(!validFd(fd,&before) || !exactSameFile(&before,&expected)){
            if(fd>=0)close(fd);
            close(pinned);
            return deny("BBX_SNAPSHOT_WRONG_FILE",87);
        }

        unsigned char buffer[BBX_SNAPSHOT_MAX];
        size_t count=(size_t)before.st_size,offset=0;
        bool okay=true;
        while(offset<count){
            ssize_t n=read(fd,buffer+offset,count-offset);
            if(n<0 && errno==EINTR)continue;
            if(n<=0){okay=false;break;}
            offset+=(size_t)n;
        }
        unsigned char extra=0;
        ssize_t trailing;
        do{trailing=read(fd,&extra,1);}while(trailing<0 && errno==EINTR);
        struct stat after;
        if(!okay || trailing!=0 || !validFd(fd,&after) ||
           !exactSameFile(&before,&after) ||
           before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec ||
           before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec ||
           before.st_ctimespec.tv_sec!=after.st_ctimespec.tv_sec ||
           before.st_ctimespec.tv_nsec!=after.st_ctimespec.tv_nsec){
            secure_wipe(buffer,sizeof(buffer));
            close(fd);close(pinned);
            return deny("BBX_SNAPSHOT_CHANGED_OR_UNREADABLE",87);
        }
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        if(!CC_SHA256(buffer,(CC_LONG)count,digest)){
            secure_wipe(buffer,sizeof(buffer));
            close(fd);close(pinned);
            return deny("BBX_SNAPSHOT_HASH_FAILED",87);
        }
        secure_wipe(buffer,sizeof(buffer));
        close(fd);close(pinned);
        printf("BBX_SNAPSHOT_READ %zu ",count);
        for(size_t i=0;i<CC_SHA256_DIGEST_LENGTH;i++)
            printf("%02x",(unsigned)digest[i]);
        putchar('\n');fflush(stdout);
        secure_wipe(digest,sizeof(digest));
        return 0;
    }
}
