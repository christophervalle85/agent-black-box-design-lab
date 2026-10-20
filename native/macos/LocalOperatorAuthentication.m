/*
 * Agent Black Box v0.8 — disposable macOS LocalAuthentication diagnostic.
 *
 * This standalone helper is NOT an operator approval authority, not called
 * by the HTTP server / MCP gateway, and never accesses any user documents.
 * A successful OS prompt must NOT be interpreted as a signed transfer grant.
 *
 * All CLI choices are fixed. There is no caller-controlled prompt text,
 * filesystem path, token, digest, operator assertion or approval payload.
 */
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *marker,int code) {
    fprintf(stdout,"%s\n",marker);
    fflush(stdout);
    return code;
}
int main(int argc,const char *argv[]) {
    @autoreleasepool {
        if(argc!=2)return fail("BBX_LOCAL_AUTH_BAD_ARGS",90);
        /*
         * The generic device-owner policy can succeed via a paired Apple
         * Watch, Touch ID, or account password. For cancellation diagnostics,
         * offer a separately labeled biometric-only policy that deliberately
         * excludes Watch/password fallback. Never silently switch policy.
         */
        const BOOL touchIDOnly=strncmp(argv[1],"touchid-",8)==0;
        const char *action=touchIDOnly?argv[1]+8:argv[1];
        if(strcmp(action,"probe")!=0 &&
           strcmp(action,"approve")!=0 && strcmp(action,"cancel")!=0)
            return fail("BBX_LOCAL_AUTH_BAD_ARGS",90);
        const BOOL probe=strcmp(action,"probe")==0;
        const BOOL requireSuccess=strcmp(action,"approve")==0;
        const LAPolicy policy=touchIDOnly?
            LAPolicyDeviceOwnerAuthenticationWithBiometrics:
            LAPolicyDeviceOwnerAuthentication;
        LAContext *context=[[LAContext alloc]init];
        // Request a fresh Touch ID interaction, never intentionally reuse a
        // cached biometric success from this synthetic test context.
        context.touchIDAuthenticationAllowableReuseDuration=0;
        NSError *preflightError=nil;
        if(![context canEvaluatePolicy:policy error:&preflightError]) {
            // No fallback to password/Watch for biometric-only experiments.
            // Deliberately omit localized error/user/account details.
            return touchIDOnly?
                fail("BBX_LOCAL_AUTH_TOUCHID_UNAVAILABLE",88):
                fail("BBX_LOCAL_AUTH_UNAVAILABLE",82);
        }
        if(probe)return touchIDOnly?
            fail("BBX_LOCAL_AUTH_TOUCHID_AVAILABLE",0):
            fail("BBX_LOCAL_AUTH_AVAILABLE",0);

        NSString *reason=touchIDOnly?
            @"Agent Black Box Touch ID only: synthetic authentication; no files changed.":
            @"Agent Black Box synthetic bbx-test-auth.txt review; no file will be changed.";
        dispatch_semaphore_t completed=dispatch_semaphore_create(0);
        __block BOOL succeeded=NO;
        __block NSInteger errorCode=0;
        __block BOOL localAuthenticationError=NO;
        [context evaluatePolicy:policy
                 localizedReason:reason
                           reply:^(BOOL success,NSError *error) {
            succeeded=success && error==nil;
            errorCode=error.code;
            localAuthenticationError=error &&
                [error.domain isEqualToString:LAErrorDomain];
            dispatch_semaphore_signal(completed);
        }];
        const long waitResult=dispatch_semaphore_wait(completed,
            dispatch_time(DISPATCH_TIME_NOW,75LL*NSEC_PER_SEC));
        if(waitResult!=0) {
            [context invalidate];
            return fail("BBX_LOCAL_AUTH_TIMED_OUT",84);
        }
        [context invalidate];
        if(succeeded) {
            if(requireSuccess)return touchIDOnly?
                fail("BBX_LOCAL_AUTH_TOUCHID_SUCCEEDED",0):
                fail("BBX_LOCAL_AUTH_SUCCEEDED",0);
            // Successful authentication is NEVER cancellation evidence.
            return touchIDOnly?
                fail("BBX_LOCAL_AUTH_TOUCHID_UNEXPECTED_SUCCESS",85):
                fail("BBX_LOCAL_AUTH_UNEXPECTED_SUCCESS",85);
        }
        if(localAuthenticationError && errorCode==LAErrorUserCancel) {
            if(!requireSuccess)return touchIDOnly?
                fail("BBX_LOCAL_AUTH_TOUCHID_USER_CANCELLED",83):
                fail("BBX_LOCAL_AUTH_USER_CANCELLED",83);
            return touchIDOnly?
                fail("BBX_LOCAL_AUTH_TOUCHID_CANCELLED_WHEN_SUCCESS_REQUIRED",86):
                fail("BBX_LOCAL_AUTH_CANCELLED_WHEN_SUCCESS_REQUIRED",86);
        }
        return touchIDOnly?
            fail("BBX_LOCAL_AUTH_TOUCHID_DENIED_OR_UNAVAILABLE",87):
            fail("BBX_LOCAL_AUTH_DENIED_OR_UNAVAILABLE",87);
    }
}
