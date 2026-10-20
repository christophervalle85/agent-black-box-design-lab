/*
 * Agent Black Box v0.8 Phase 5 — synthetic Touch ID review identity fixture.
 * NO filesystem access, no controller or MCP access, and no transport token.
 * The caller must bind these six fixed metadata fields to an audited,
 * unexpired, one-time in-process review BEFORE dispatching this helper.
 *
 * This ad-hoc executable does NOT prove a Developer ID-signed producer or a
 * particular human identity. It is strictly a macOS on-device experiment.
 */
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static bool hexlower(const char *s,size_t expected){
    if(!s || strnlen(s,expected+1)!=expected)return false;
    for(size_t i=0;i<expected;i++)
        if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))
            return false;
    return true;
}
static bool uuid4(const char *s){
    if(!s || strnlen(s,37)!=36)return false;
    for(size_t i=0;i<36;i++){
        if(i==8||i==13||i==18||i==23){if(s[i]!='-')return false;}
        else if(!((s[i]>='0'&&s[i]<='9')||
                  (s[i]>='a'&&s[i]<='f')))return false;
    }
    return s[14]=='4' && strchr("89ab",s[19])!=NULL;
}
static bool note_name(const char *s){
    if(!s)return false;
    size_t n=strnlen(s,70);
    if(n<14||n>64||strncmp(s,"bbx-test-",9)!=0||
       strcmp(s+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        char c=s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
static bool byte_count(const char *s){
    if(!s||s[0]<'1'||s[0]>'9'||strnlen(s,6)>4)return false;
    for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return false;
    long n=strtol(s,NULL,10);
    return n>=1 && n<=2000;
}
int main(int argc,const char *argv[]){
    @autoreleasepool {
        // argv: UUID, operation, synthetic note, byte size, digest, nonce.
        if(argc!=7 || !uuid4(argv[1]) ||
           (strcmp(argv[2],"import")!=0 && strcmp(argv[2],"export")!=0) ||
           !note_name(argv[3]) || !byte_count(argv[4]) ||
           !hexlower(argv[5],64) || !uuid4(argv[6])){
            puts("BBX_TRANSFER_AUTH_BAD_ARGS");
            return 90;
        }
        LAContext *context=[[LAContext alloc]init];
        context.touchIDAuthenticationAllowableReuseDuration=0;
        NSError *error=nil;
        if(![context canEvaluatePolicy:
            LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]){
            puts("BBX_TRANSFER_AUTH_UNAVAILABLE");
            return 82;
        }
        NSString *operation=[NSString stringWithUTF8String:argv[2]];
        NSString *name=[NSString stringWithUTF8String:argv[3]];
        NSString *reason=[NSString stringWithFormat:
            @"Agent Black Box synthetic %@ %@ (%s bytes, SHA256 %.10s). No files change.",
            operation,name,argv[4],argv[5]];
        dispatch_semaphore_t semaphore=dispatch_semaphore_create(0);
        __block BOOL succeeded=NO;
        __block BOOL userCancelled=NO;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                 localizedReason:reason
                           reply:^(BOOL success,NSError *localError){
            succeeded=success && localError==nil;
            userCancelled=localError &&
                [localError.domain isEqualToString:LAErrorDomain] &&
                localError.code==LAErrorUserCancel;
            dispatch_semaphore_signal(semaphore);
        }];
        const long waited=dispatch_semaphore_wait(semaphore,
            dispatch_time(DISPATCH_TIME_NOW,25LL*NSEC_PER_SEC));
        if(waited!=0){
            [context invalidate];
            puts("BBX_TRANSFER_AUTH_TIMED_OUT");
            return 84;
        }
        [context invalidate];
        if(succeeded){
            printf("BBX_TRANSFER_TOUCHID_AUTHENTICATED %s %s %s %s %s %s\n",
                   argv[1],argv[6],argv[5],argv[2],argv[3],argv[4]);
            return 0;
        }
        if(userCancelled){
            printf("BBX_TRANSFER_TOUCHID_USER_CANCELLED %s %s %s %s %s %s\n",
                   argv[1],argv[6],argv[5],argv[2],argv[3],argv[4]);
            return 83;
        }
        puts("BBX_TRANSFER_AUTH_DENIED");
        return 87;
    }
}
