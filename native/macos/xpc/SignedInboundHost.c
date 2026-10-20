/*
 * Phase 6 signed incoming-peer OS negative acceptance (SYNTHETIC ONLY).
 * Two independently signed executables with the SAME team, but DIFFERENT
 * signing identifiers, reside in one disposable app. The trusted host
 * keeps one XPC connection alive while the wrong-identity helper attempts
 * to send a valid fixed payload. A worker-only test counter must remain
 * unchanged on the SAME running worker PID after the unauthorized attempt.
 *
 * NOT production permission or filesystem access. No user file bytes,
 * Touch ID tokens, paths, or credentials cross XPC.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <CommonCrypto/CommonDigest.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "PeerRequirementGate.h"

extern char **environ;

#define BBX_WORKER_ID "dev.agentblackbox.xpc-snapshot-receipt.worker"
#define BBX_WRONG_HELPER "BlackBoxTransferReceiptWrongHost"
static const unsigned char fixture[]="BBX synthetic XPC transfer bytes.\n";

static void hexSha256(char output[65]){
    unsigned char sum[CC_SHA256_DIGEST_LENGTH];
    const char alphabet[]="0123456789abcdef";
    CC_SHA256(fixture,(CC_LONG)(sizeof(fixture)-1),sum);
    for(size_t i=0;i<sizeof(sum);i++){
        output[2*i]=alphabet[sum[i]>>4];
        output[2*i+1]=alphabet[sum[i]&15];
    }
    output[64]='\0';
    if(memset_s(sum,sizeof(sum),0,sizeof(sum))!=0)abort();
}
static xpc_connection_t connectWorker(void){
    xpc_connection_t peer=xpc_connection_create(BBX_WORKER_ID,
        dispatch_get_global_queue(QOS_CLASS_DEFAULT,0));
    if(!peer)return NULL;
    if(bbx_install_same_team_peer_requirement(peer,BBX_WORKER_ID)!=0){
        xpc_connection_cancel(peer);
        xpc_release(peer);
        return NULL;
    }
    xpc_connection_set_event_handler(peer,^(xpc_object_t event){
        (void)event;
    });
    xpc_connection_resume(peer);
    return peer;
}
static xpc_object_t receipt(xpc_connection_t peer){
    char hex[65];
    hexSha256(hex);
    xpc_object_t req=xpc_dictionary_create(NULL,NULL,0);
    if(!req)return NULL;
    xpc_dictionary_set_string(req,"method","snapshot_receipt");
    xpc_dictionary_set_string(req,"name","bbx-test-xpc-payload.txt");
    xpc_dictionary_set_string(req,"nonce","0123456789abcdef0123456789abcdef");
    xpc_dictionary_set_string(req,"sha256",hex);
    xpc_dictionary_set_data(req,"payload",fixture,sizeof(fixture)-1);
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,req);
    xpc_release(req);
    return reply;
}
static bool goodReceipt(xpc_connection_t peer){
    xpc_object_t reply=receipt(peer);
    if(!reply)return false;
    bool okay=xpc_get_type(reply)==XPC_TYPE_DICTIONARY;
    const char *status=okay?xpc_dictionary_get_string(reply,"status"):NULL;
    okay=status && strcmp(status,"ACCEPTED")==0;
    xpc_release(reply);
    return okay;
}
static bool workerStats(xpc_connection_t peer,uint64_t *pid,uint64_t *count){
    xpc_object_t req=xpc_dictionary_create(NULL,NULL,0);
    if(!req)return false;
    xpc_dictionary_set_string(req,"method","signed_inbound_stats");
    xpc_object_t reply=xpc_connection_send_message_with_reply_sync(peer,req);
    xpc_release(req);
    if(!reply)return false;
    bool valid=xpc_get_type(reply)==XPC_TYPE_DICTIONARY;
    if(valid){
        xpc_object_t p=xpc_dictionary_get_value(reply,"workerPID");
        xpc_object_t n=xpc_dictionary_get_value(reply,"delivered");
        valid=p && n && xpc_get_type(p)==XPC_TYPE_UINT64 &&
            xpc_get_type(n)==XPC_TYPE_UINT64;
        if(valid){
            *pid=xpc_dictionary_get_uint64(reply,"workerPID");
            *count=xpc_dictionary_get_uint64(reply,"delivered");
            valid=*pid>0 && *count>0;
        }
    }
    xpc_release(reply);
    return valid;
}
static bool typedDenial(xpc_connection_t peer){
    xpc_object_t reply=receipt(peer);
    if(!reply)return false;
    /* A positive handler reply is NEVER a successful denial. Apple's
     * incoming-peer gate can reject by not delivering the worker message;
     * client may see a connection error rather than peer-signing error. */
    bool failed=xpc_get_type(reply)==XPC_TYPE_ERROR &&
      (reply==XPC_ERROR_CONNECTION_INVALID ||
       reply==XPC_ERROR_CONNECTION_INTERRUPTED ||
       reply==XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT);
    xpc_release(reply);
    return failed;
}
static bool spawnWrongSibling(const char *self){
    const char *slash=strrchr(self,'/');
    if(!slash)return false;
    const size_t prefix=(size_t)(slash-self+1);
    const size_t nameLength=sizeof(BBX_WRONG_HELPER);
    if(prefix+nameLength>=MAXPATHLEN)return false;
    char path[MAXPATHLEN];
    memcpy(path,self,prefix);
    memcpy(path+prefix,BBX_WRONG_HELPER,nameLength);
    char *const argv[]={path,"wrong-host",NULL};
    posix_spawn_file_actions_t actions;
    if(posix_spawn_file_actions_init(&actions)!=0)return false;
    /* Wrong host must not leak XPC status, paths or user data to stdout. */
    int redirect=posix_spawn_file_actions_addopen(
        &actions,STDOUT_FILENO,"/dev/null",O_WRONLY,0);
    if(redirect==0)redirect=posix_spawn_file_actions_addopen(
        &actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);
    pid_t pid=0;
    int spawnResult=redirect==0?
        posix_spawn(&pid,path,&actions,NULL,argv,environ):redirect;
    posix_spawn_file_actions_destroy(&actions);
    if(spawnResult!=0)return false;
    int status=-1;
    while(waitpid(pid,&status,0)<0){
        if(errno!=EINTR)return false;
    }
    return WIFEXITED(status)&&WEXITSTATUS(status)==0;
}
int main(int argc,char *argv[]){
    if(argc!=2 || (strcmp(argv[1],"orchestrate")!=0 &&
                   strcmp(argv[1],"wrong-host")!=0))
        return 90;
    xpc_connection_t peer=connectWorker();
    if(!peer){
        puts("BBX_INBOUND_PEER_GATE_UNAVAILABLE");
        return 85;
    }
    if(strcmp(argv[1],"wrong-host")==0){
        const bool denied=typedDenial(peer);
        xpc_connection_cancel(peer);
        xpc_release(peer);
        return denied?0:87;
    }
    /* A legitimate host keeps the same worker connection alive and verifies
     * that worker delivered-count only changes for its own two probe calls.
     * This is an in-memory same-process counter, not a persistent audit. */
    uint64_t pid1=0,pid2=0,count1=0,count2=0;
    bool okay=goodReceipt(peer) &&
        workerStats(peer,&pid1,&count1) &&
        spawnWrongSibling(argv[0]) &&
        workerStats(peer,&pid2,&count2) &&
        pid1==pid2 && count1==2 && count2==3;
    xpc_connection_cancel(peer);
    xpc_release(peer);
    if(!okay){
        puts("BBX_XPC_SIGNED_INBOUND_NOT_ESTABLISHED");
        return 87;
    }
    puts("BBX_XPC_SIGNED_INBOUND_OS_REJECTED");
    return 0;
}
