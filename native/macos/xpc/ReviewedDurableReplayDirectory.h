/* TEST ONLY: private App Sandbox container directory for durable nonce markers. */
#ifndef BBX_REVIEWED_DURABLE_DIRECTORY_H
#define BBX_REVIEWED_DURABLE_DIRECTORY_H
/*
 * Private worker App Sandbox Documents container, never a path from IPC.
 * The ordinary receipt build never opens or writes any filesystem storage.
 */
static int bbx_replay_directory(void){
    @autoreleasepool {
        NSError *error=nil;
        NSURL *documents=[[NSFileManager defaultManager]
            URLForDirectory:NSDocumentDirectory
            inDomain:NSUserDomainMask
            appropriateForURL:nil create:YES error:&error];
        if(!documents)return -1;
        const char *path=[documents fileSystemRepresentation];
        if(!path || !strstr(path,"/Library/Containers/") ||
           !strstr(path,"/Data/Documents"))return -1;
        const int parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(parent<0)return -1;
        if(mkdirat(parent,"AgentBlackBoxReviewedReplay",0700)<0){
            if(errno!=EEXIST){close(parent);return -1;}
        }else if(fsync(parent)!=0){
            close(parent);
            return -1;
        }
        const int directory=openat(parent,"AgentBlackBoxReviewedReplay",
                                   O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(parent);
        if(directory<0)return -1;
        struct stat info={0};
        if(fstat(directory,&info)!=0 || !S_ISDIR(info.st_mode) ||
           info.st_uid!=geteuid() || (info.st_mode&077)!=0){
            close(directory);
            return -1;
        }
        return directory;
    }
}
#endif
