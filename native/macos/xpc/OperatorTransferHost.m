/*
 * v0.8 OPERATOR-ONLY experimental import/export, never an MCP tool.
 * The human selects the source/destination in AppKit. No Node/model-provided
 * host path, security bookmark, destination or approval token is accepted.
 * The only worker capability is allowlisted bbx-test-*.txt in its sandbox
 * Documents root. The worker independently enforces signed host identity.
 *
 * Import: selected fd -> bounded UTF-8 immutable snapshot -> fresh Touch ID
 * -> sandboxed XPC exclusive create -> exact worker readback.
 * Export: worker-owned test note -> NSSavePanel -> fresh Touch ID ->
 * O_EXCL/O_NOFOLLOW new file -> fsync. No overwrite or silent retry.
 *
 * This does NOT use the test-only fixed-byte RSA signing authority. Native
 * operator confirmation is real, but production authorization/Keychain ACL,
 * remote MCP policy, source race immunity and recovery are not established.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

static const char serviceName[]="dev.agentblackbox.xpc-authority.worker";
/* Fixed, content-free diagnostic identifiers. No user-selected path,
   filename, errno, payload or Keychain information is ever printed. */
static int denyImport(const char *reason){
    printf("BBX_OPERATOR_IMPORT_DENIED_%s\n",reason);
    fflush(stdout);
    return 87;
}
static bool safeName(const char *text){
    if(!text)return false;
    size_t n=strnlen(text,80);
    if(n<14||n>64||strncmp(text,"bbx-test-",9)!=0||
       strcmp(text+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        const char c=text[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||(c>='A'&&c<='Z')||
             c=='_'||c=='-'))return false;
    }
    return true;
}
static void sha256Hex(NSData *data,char hash[65]){
    unsigned char digest[CC_SHA256_DIGEST_LENGTH]={0};
    CC_SHA256([data bytes],(CC_LONG)[data length],digest);
    const char alphabet[]="0123456789abcdef";
    for(int i=0;i<CC_SHA256_DIGEST_LENGTH;i++){
        hash[2*i]=alphabet[digest[i]>>4];
        hash[2*i+1]=alphabet[digest[i]&15];
    }
    hash[64]='\0';
}
static bool deviceOwnerConsent(NSString *operation,const char *name,
                               size_t length,const char *digest){
    LAContext *context=[LAContext new];
    context.touchIDAuthenticationAllowableReuseDuration=0;
    NSError *available=nil;
    if(![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                            error:&available])return false;
    NSString *why=[NSString stringWithFormat:
        @"Agent Black Box test %@: %s, %zu bytes, SHA256 %.12s. No other files.",
        operation,name,length,digest];
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    __block BOOL approved=NO;
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:why reply:^(BOOL ok,NSError *error){
                approved=ok&&error==nil;
                dispatch_semaphore_signal(done);
            }];
    const long timeout=dispatch_semaphore_wait(
        done,dispatch_time(DISPATCH_TIME_NOW,40*NSEC_PER_SEC));
    [context invalidate];
    return timeout==0&&approved;
}
static NSData *selectedRegularText(NSURL *url,const char *fixture,
                                   const char **why){
    *why="SOURCE_URL";
    if(!url||![url isFileURL])return nil;
    const char *path=[url fileSystemRepresentation];
    *why="SOURCE_PATH";
    if(!path||path[0]!='/'||strnlen(path,PATH_MAX)>=PATH_MAX)return nil;
    *why="SOURCE_OPEN";
    const int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return nil;
    struct stat before={0},after={0};
    NSData *data=nil;
    *why="SOURCE_POLICY";
    if(fstat(fd,&before)==0 && S_ISREG(before.st_mode) &&
       before.st_uid==geteuid() && before.st_nlink==1){
        if(fixture){
            struct stat expected={0};
            *why="FIXTURE_MISMATCH";
            if(lstat(fixture,&expected)!=0||!S_ISREG(expected.st_mode)||
               expected.st_uid!=geteuid()||expected.st_nlink!=1||
               expected.st_dev!=before.st_dev||
               expected.st_ino!=before.st_ino){
                close(fd);
                return nil;
            }
        }
        *why="SOURCE_SIZE";
        if(before.st_size>0&&before.st_size<=2000){
            unsigned char bytes[2001]={0};
            size_t used=0;
            while(used<(size_t)before.st_size){
                ssize_t n=read(fd,bytes+used,(size_t)before.st_size-used);
                if(n<=0)break;
                used+=(size_t)n;
            }
            unsigned char extra=0;
            *why="SOURCE_CHANGED";
            if(used==(size_t)before.st_size&&read(fd,&extra,1)==0&&
               fstat(fd,&after)==0&&before.st_dev==after.st_dev&&
               before.st_ino==after.st_ino&&
               before.st_size==after.st_size&&
               before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec&&
               before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec){
                *why="SOURCE_TEXT";
                if(memchr(bytes,0,used)==NULL){
                    NSData *candidate=[NSData dataWithBytes:bytes length:used];
                    if([[NSString alloc] initWithData:candidate
                                     encoding:NSUTF8StringEncoding])data=candidate;
                }
            }
            memset(bytes,0,sizeof(bytes));
        }
    }
    if(close(fd)!=0){*why="SOURCE_CLOSE";return nil;}
    return data;
}

#ifdef BBX_OPERATOR_NEGATIVE_DIAGNOSTICS
/* Disposable acceptance-only diagnostics. These entry points cannot be
   built into the ordinary operator executable and never connect to XPC,
   request Touch ID, or create a note. Each fixture comes from the local
   harness, not an MCP/model-supplied path. */
static bool negativeRegularFixture(const char *path,struct stat *st){
    if(!path||path[0]!='/'||strnlen(path,PATH_MAX)>=PATH_MAX)return false;
    return lstat(path,st)==0&&S_ISREG(st->st_mode)&&
        st->st_uid==geteuid()&&st->st_nlink==1&&
        st->st_size>0&&st->st_size<=2000;
}
static bool negativeLinkFixture(const char *link,const char *target,
                                struct stat *linkInfo,struct stat *targetInfo){
    if(!link||link[0]!='/'||strnlen(link,PATH_MAX)>=PATH_MAX||
       !negativeRegularFixture(target,targetInfo))return false;
    if(lstat(link,linkInfo)!=0||!S_ISLNK(linkInfo->st_mode)||
       linkInfo->st_uid!=geteuid())return false;
    NSString *l=[NSString stringWithUTF8String:link];
    NSString *t=[NSString stringWithUTF8String:target];
    if(!l||!t||
       ![[l stringByDeletingLastPathComponent]
          isEqualToString:[t stringByDeletingLastPathComponent]]||
       ![[l lastPathComponent] isEqualToString:@"bbx-test-link.txt"]||
       ![[t lastPathComponent] isEqualToString:@"bbx-test-target.txt"])
        return false;
    char destination[PATH_MAX]={0};
    ssize_t n=readlink(link,destination,sizeof(destination)-1);
    return n>0&&n<(ssize_t)sizeof(destination)-1&&
           strcmp(destination,"bbx-test-target.txt")==0;
}
static NSURL *negativeFileURL(const char *path){
    if(!path||path[0]!='/'||strnlen(path,PATH_MAX)>=PATH_MAX)return nil;
    NSString *string=[NSString stringWithUTF8String:path];
    return string?[NSURL fileURLWithPath:string]:nil;
}
static NSOpenPanel *negativePanel(const char *expected,NSString *message){
    NSOpenPanel *panel=[NSOpenPanel openPanel];
    panel.canChooseFiles=YES;
    panel.canChooseDirectories=NO;
    panel.allowsMultipleSelection=NO;
    panel.resolvesAliases=NO;
    panel.message=message;
    NSString *value=[NSString stringWithUTF8String:expected];
    panel.directoryURL=[NSURL fileURLWithPath:
        [value stringByDeletingLastPathComponent] isDirectory:YES];
    return panel;
}
static int negativeSymlinkOpen(const char *link,const char *target){
    struct stat l={0},t={0};
    if(!negativeLinkFixture(link,target,&l,&t))return 90;
    errno=0;
    int fd=open(link,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd>=0){close(fd);return 89;}
    if(errno!=ELOOP)return 89;
    const char *why=NULL;
    NSData *snapshot=selectedRegularText(negativeFileURL(link),NULL,&why);
    if(snapshot||!why||strcmp(why,"SOURCE_OPEN")!=0)return 89;
    puts("BBX_OPERATOR_SYMLINK_OPEN_DENIED");
    return 0;
}
static int negativeSymlinkPanel(const char *link,const char *target){
    struct stat l={0},t={0};
    if(!negativeLinkFixture(link,target,&l,&t))return 90;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp activateIgnoringOtherApps:YES];
    NSOpenPanel *panel=negativePanel(link,
        @"TEST: select ONLY bbx-test-link.txt (symbolic link). No Touch ID or import.");
    if([panel runModal]!=NSModalResponseOK){
        puts("BBX_OPERATOR_SYMLINK_PICKER_CANCELLED");
        return 88;
    }
    NSURL *url=[panel URLs].firstObject;
    const char *path=[url fileSystemRepresentation];
    struct stat selected={0};
    if(!path||lstat(path,&selected)!=0){
        puts("BBX_OPERATOR_SYMLINK_PICKER_OTHER_SELECTION");
        return 88;
    }
    if(S_ISLNK(selected.st_mode)&&
       selected.st_dev==l.st_dev&&selected.st_ino==l.st_ino){
        const char *why=NULL;
        NSData *snapshot=selectedRegularText(url,NULL,&why);
        if(snapshot||!why||strcmp(why,"SOURCE_OPEN")!=0)return 89;
        puts("BBX_OPERATOR_SYMLINK_PICKER_DENIED");
        return 0;
    }
    if(S_ISREG(selected.st_mode)&&selected.st_dev==t.st_dev&&
       selected.st_ino==t.st_ino){
        puts("BBX_OPERATOR_SYMLINK_PICKER_RESOLVED_TARGET");
        return 88;
    }
    puts("BBX_OPERATOR_SYMLINK_PICKER_OTHER_SELECTION");
    return 88;
}
static int negativeWrongSelectionPanel(const char *allowed,const char *wrong){
    struct stat a={0},w={0};
    if(!negativeRegularFixture(allowed,&a)||
       !negativeRegularFixture(wrong,&w)||
       (a.st_dev==w.st_dev&&a.st_ino==w.st_ino))return 90;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp activateIgnoringOtherApps:YES];
    NSOpenPanel *panel=negativePanel(allowed,
        @"TEST: select ONLY bbx-test-other.txt (wrong fixture). No Touch ID or import.");
    if([panel runModal]!=NSModalResponseOK){
        puts("BBX_OPERATOR_WRONG_PICKER_CANCELLED");
        return 88;
    }
    NSURL *url=[panel URLs].firstObject;
    const char *path=[url fileSystemRepresentation];
    struct stat selected={0};
    if(!path||lstat(path,&selected)!=0||!S_ISREG(selected.st_mode)||
       selected.st_dev!=w.st_dev||selected.st_ino!=w.st_ino){
        puts("BBX_OPERATOR_WRONG_PICKER_OTHER_SELECTION");
        return 88;
    }
    const char *why=NULL;
    NSData *snapshot=selectedRegularText(url,allowed,&why);
    if(snapshot||!why||strcmp(why,"FIXTURE_MISMATCH")!=0)return 89;
    puts("BBX_OPERATOR_WRONG_FIXTURE_DENIED");
    return 0;
}
#endif

static xpc_object_t request(xpc_connection_t peer,const char *method,
                            const char *note,const char *content){
    if(!peer||!method||!safeName(note))return NULL;
    xpc_object_t msg=xpc_dictionary_create(NULL,NULL,0);
    if(!msg)return NULL;
    xpc_dictionary_set_string(msg,"method",method);
    xpc_dictionary_set_string(msg,"path",note);
    if(content)xpc_dictionary_set_string(msg,"content",content);
    /* The harness supervises this blocked native process. A lost reply
       after a possible write is UNKNOWN, never a legitimate retry. */
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,msg);
    xpc_release(msg);
    if(!reply||xpc_get_type(reply)!=XPC_TYPE_DICTIONARY){
        if(reply)xpc_release(reply);
        return NULL;
    }
    return reply;
}
static BOOL accepted(xpc_object_t reply){
    return reply&&xpc_get_type(reply)==XPC_TYPE_DICTIONARY &&
           xpc_dictionary_get_bool(reply,"ok") &&
           xpc_dictionary_get_int64(reply,"workerPID")>0 &&
           xpc_dictionary_get_int64(reply,"workerPID")!=(int64_t)getpid();
}
static NSData *readNote(xpc_connection_t peer,const char *name){
    xpc_object_t r=request(peer,"read_note",name,NULL);
    NSData *result=nil;
    if(accepted(r)){
        const char *value=xpc_dictionary_get_string(r,"content");
        if(value){
            size_t count=strnlen(value,2001);
            if(count>0&&count<=2000)result=[NSData dataWithBytes:value length:count];
        }
    }
    if(r)xpc_release(r);
    return result;
}
static int importSelected(xpc_connection_t peer,const char *fixture){
    NSOpenPanel *panel=[NSOpenPanel openPanel];
    panel.canChooseFiles=YES;
    panel.canChooseDirectories=NO;
    panel.allowsMultipleSelection=NO;
    panel.resolvesAliases=NO;
    panel.message=fixture?
        @"TEST: Select ONLY bbx-test-operator-fixture.txt (a generated disposable file).":
        @"Select ONE small, non-sensitive UTF-8 text file (1–2000 bytes).";
    if(fixture){
        NSString *expected=[NSString stringWithUTF8String:fixture];
        if(!expected)return denyImport("FIXTURE_PATH");
        panel.directoryURL=[NSURL fileURLWithPath:
            [expected stringByDeletingLastPathComponent] isDirectory:YES];
    }
    if([panel runModal]!=NSModalResponseOK){
        if(fixture){
            puts("BBX_OPERATOR_IMPORT_CANCELLED_PICKER");
            fflush(stdout);
        }
        return 83;
    }
    const char *snapshotReason=NULL;
    NSData *snapshot=selectedRegularText([panel URLs].firstObject,
                                         fixture,&snapshotReason);
    if(!snapshot)return denyImport(snapshotReason?snapshotReason:"SOURCE_UNKNOWN");
    NSString *uuid=[[[NSUUID UUID] UUIDString] lowercaseString];
    NSString *name=[NSString stringWithFormat:@"bbx-test-%@.txt",uuid];
    const char *note=[name UTF8String];
    char digest[65]={0};
    sha256Hex(snapshot,digest);
    if(!safeName(note))return denyImport("NOTE_SCHEMA");
    NSString *text=[[NSString alloc] initWithData:snapshot
                                        encoding:NSUTF8StringEncoding];
    if(!text||[text length]==0)return denyImport("NOTE_ENCODING");
    if(!deviceOwnerConsent(@"IMPORT",note,[snapshot length],digest))return 83;
    /* No host filesystem paths cross the XPC boundary. */
    xpc_object_t response=request(peer,"write_note",note,[text UTF8String]);
    const BOOL committed=accepted(response);
    if(response)xpc_release(response);
    if(!committed)return 89; // unknown after possible worker commit
    NSData *readback=readNote(peer,note);
    if(!readback||![snapshot isEqualToData:readback])return 89;
    printf("BBX_OPERATOR_IMPORT_COMMITTED %s %zu %s\n",
           note,(size_t)[snapshot length],digest);
    fflush(stdout);
    return 0;
}
static int exclusiveExport(NSData *payload,NSURL *url){
    if(!url||![url isFileURL])return 87;
    NSURL *parentURL=[url URLByDeletingLastPathComponent];
    const char *folder=[parentURL fileSystemRepresentation];
    const char *leaf=[[url lastPathComponent] fileSystemRepresentation];
    if(!folder||folder[0]!='/'||strnlen(folder,PATH_MAX)>=PATH_MAX||
       !leaf||leaf[0]=='\0'||strlen(leaf)>255||
       strcmp(leaf,".")==0||strcmp(leaf,"..")==0||
       strchr(leaf,'/')!=NULL)return 87;
    /* Hold the human-selected parent directory descriptor across create,
       readback and fsync. Never follow a destination leaf symlink or
       overwrite a preexisting user file. */
    int dir=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return 87;
    int status=0;
    int fd=openat(dir,leaf,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){close(dir);return 87;}
    struct stat created={0};
    if(fstat(fd,&created)!=0||!S_ISREG(created.st_mode)||
       created.st_uid!=geteuid()||created.st_nlink!=1||
       (created.st_mode&0777)!=0600)status=89;
    size_t off=0;
    const unsigned char *data=[payload bytes];
    while(status==0&&off<[payload length]){
        ssize_t n=write(fd,data+off,[payload length]-off);
        if(n<=0){status=89;break;}
        off+=(size_t)n;
    }
    if(status==0&&fsync(fd)!=0)status=89;
    if(close(fd)!=0)status=89;
    /* Do not unlink on failure: an already created destination can be a
       partial or committed file and must be reconciled manually. */
    if(status==0){
        int verify=openat(dir,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(verify<0)status=89;
        else{
            struct stat observed={0};
            unsigned char readback[2001]={0};
            size_t used=0;
            if(fstat(verify,&observed)!=0||!S_ISREG(observed.st_mode)||
               observed.st_dev!=created.st_dev||
               observed.st_ino!=created.st_ino||
               observed.st_nlink!=1||
               observed.st_size!=(off_t)[payload length])status=89;
            while(status==0&&used<[payload length]){
                ssize_t n=read(verify,readback+used,[payload length]-used);
                if(n<=0){status=89;break;}
                used+=(size_t)n;
            }
            if(status==0&&memcmp(readback,data,used)!=0)status=89;
            memset(readback,0,sizeof(readback));
            if(close(verify)!=0)status=89;
        }
    }
    if(status==0&&fsync(dir)!=0)status=89;
    if(close(dir)!=0)status=89;
    return status;
}
/* Independent non-destructive negative gate: the wrapper creates this
   preexisting disposable fixture. Verify exact known bytes and inode before
   and after exclusiveExport refuses O_EXCL. No picker or biometric prompt
   is required because no export is authorized. */
static int rejectExistingExport(xpc_connection_t peer,
                                const char *name,const char *path){
    const char sentinel[]="BBX existing destination preserved\n";
    if(!safeName(name)||!path||path[0]!='/'||
       strnlen(path,PATH_MAX)>=PATH_MAX)return 90;
    NSURL *destination=[NSURL fileURLWithPath:
        [NSString stringWithUTF8String:path]];
    const char *reason=NULL;
    NSData *before=selectedRegularText(destination,NULL,&reason);
    NSData *expected=[NSData dataWithBytes:sentinel length:sizeof(sentinel)-1];
    if(!before||![before isEqualToData:expected])return 90;
    NSData *payload=readNote(peer,name);
    if(!payload)return 90;
    if(exclusiveExport(payload,destination)!=87)return 89;
    NSData *after=selectedRegularText(destination,NULL,&reason);
    if(!after||![after isEqualToData:expected])return 89;
    puts("BBX_OPERATOR_EXPORT_OVERWRITE_DENIED");
    fflush(stdout);
    return 0;
}
static int exportSelected(xpc_connection_t peer,const char *name){
    if(!safeName(name))return 87;
    NSData *content=readNote(peer,name);
    if(!content)return 87;
    NSString *check=[[NSString alloc] initWithData:content
                                          encoding:NSUTF8StringEncoding];
    if(!check)return 87;
    char digest[65]={0};
    sha256Hex(content,digest);
    NSSavePanel *panel=[NSSavePanel savePanel];
    panel.nameFieldStringValue=[NSString stringWithUTF8String:name];
    panel.message=@"Choose a NEW destination file for this test note. Existing files cannot be overwritten.";
    if([panel runModal]!=NSModalResponseOK)return 83;
    NSURL *selected=[panel URL];
    if(!selected||![selected isFileURL])return 87;
    // SavePanel may show replace confirmation; explicit O_EXCL still denies.
    if(!deviceOwnerConsent(@"EXPORT",name,[content length],digest))return 83;
    const int outcome=exclusiveExport(content,selected);
    if(outcome!=0)return outcome;
    printf("BBX_OPERATOR_EXPORT_COMMITTED %s %zu %s\n",
           name,(size_t)[content length],digest);
    fflush(stdout);
    return 0;
}
int main(int argc,const char *argv[]){
    @autoreleasepool {
        if(argc<2||argc>4)return 90;
#ifdef BBX_OPERATOR_NEGATIVE_DIAGNOSTICS
        if(argc==4&&strcmp(argv[1],"test-symlink-open")==0)
            return negativeSymlinkOpen(argv[2],argv[3]);
        if(argc==4&&strcmp(argv[1],"test-symlink-panel")==0)
            return negativeSymlinkPanel(argv[2],argv[3]);
        if(argc==4&&strcmp(argv[1],"test-wrong-panel")==0)
            return negativeWrongSelectionPanel(argv[2],argv[3]);
#endif
        const BOOL importing=argc==2&&strcmp(argv[1],"import")==0;
        const BOOL fixtureImport=argc==3&&
                                 strcmp(argv[1],"import-fixture")==0;
        const BOOL exporting=argc==3&&strcmp(argv[1],"export")==0&&
                             safeName(argv[2]);
        const BOOL denyExisting=argc==4&&
                                strcmp(argv[1],"export-overwrite-test")==0&&
                                safeName(argv[2]);
        if(!importing&&!fixtureImport&&!exporting&&!denyExisting)return 90;
        if(fixtureImport&&(!argv[2]||argv[2][0]!='/'||
                          strnlen(argv[2],PATH_MAX)>=PATH_MAX))
            return denyImport("FIXTURE_PATH");
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [NSApp activateIgnoringOtherApps:YES];
        xpc_connection_t peer=xpc_connection_create(serviceName,
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0));
        if(!peer)return importing||fixtureImport?
            denyImport("XPC_SETUP"):87;
        xpc_connection_set_event_handler(peer,^(xpc_object_t event){
            (void)event; // request() validates each reply explicitly.
        });
        xpc_connection_resume(peer);
        int result=(importing||fixtureImport)?
            importSelected(peer,fixtureImport?argv[2]:NULL):
            denyExisting?rejectExistingExport(peer,argv[2],argv[3]):
            exportSelected(peer,argv[2]);
        xpc_connection_cancel(peer);
        xpc_release(peer);
        return result;
    }
}
