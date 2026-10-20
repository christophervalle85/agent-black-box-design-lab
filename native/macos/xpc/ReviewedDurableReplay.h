/*
 * v0.8 TEST-ONLY persistent native receipt-consumption primitive.
 * A successful receipt reserves the reviewed UUIDv4 nonce DURABLY before
 * acknowledging success. Works across process restarts, unlike the old
 * process-local 64-nonce cache. No payload bytes or arbitrary paths enter it.
 *
 * The caller must supply a trusted worker-owned sandbox directory FD;
 * directory path and signing authority must NEVER come from XPC arguments.
 * Same-user filesystem compromise, removal/rollback of this directory,
 * audit-controller identity, and actual data commits are NOT covered.
 *
 * Atomic O_EXCL file creation prevents duplicate nonce consumption even
 * across two distinct worker processes. A write/fsync failure leaves a
 * possibly spent marker rather than allowing unsafe retry.
 */
#ifndef BBX_REVIEWED_DURABLE_REPLAY_H
#define BBX_REVIEWED_DURABLE_REPLAY_H
#include "ReviewedTransactionContract.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    BBX_REPLAY_STORE_DENIED=0,
    BBX_REPLAY_ALREADY_SPENT=1,
    BBX_REPLAY_FRESH_COMMITTED=2
} BBXReplayDecision;
static inline BBXReplayDecision bbx_reviewed_replay_reserve(
    int directory,const char *nonce,const char *transactionId){
    if(directory<0 || !bbx_reviewed_uuid4(nonce) ||
       !bbx_reviewed_lowerhex(transactionId,64))
        return BBX_REPLAY_STORE_DENIED;
    struct stat dirStat={0};
    if(fstat(directory,&dirStat)!=0 || !S_ISDIR(dirStat.st_mode) ||
       dirStat.st_uid!=geteuid() || (dirStat.st_mode&077)!=0)
        return BBX_REPLAY_STORE_DENIED;
    char name[60];
    const int length=snprintf(name,sizeof(name),"nonce-%s.spent",nonce);
    if(length<1 || (size_t)length>=sizeof(name))
        return BBX_REPLAY_STORE_DENIED;
    const int fd=openat(directory,name,
        O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){
        if(errno==EEXIST)return BBX_REPLAY_ALREADY_SPENT;
        return BBX_REPLAY_STORE_DENIED;
    }
    /* Immutable forensic hint: no source path, payload, or approval secret.
       There is no cleanup on any I/O failure: ambiguity MUST burn the nonce. */
    char evidence[112];
    const int n=snprintf(evidence,sizeof(evidence),"bbx-replay-v1\n%s\n",
                         transactionId);
    bool okay=n>0 && (size_t)n<sizeof(evidence);
    if(okay){
        ssize_t bytes=write(fd,evidence,(size_t)n);
        okay=bytes==n;
    }
    if(okay)okay=fsync(fd)==0;
    if(close(fd)!=0)okay=false;
    if(okay)okay=fsync(directory)==0;
    return okay?BBX_REPLAY_FRESH_COMMITTED:BBX_REPLAY_STORE_DENIED;
}
/*
 * Read-only local forensic observation of a particular reviewed transaction.
 * Observing NO_MARKER is NOT proof the transaction never ran, and NEVER
 * authorizes retry. Corrupt, symlinked, partial, or wrong-transaction
 * records are UNVERIFIABLE, not "missing".
 *
 * No attacker-supplied path: nonce is strictly UUIDv4 and directory is an
 * already authenticated sandbox-owned directory descriptor.
 */
typedef enum {
    BBX_REPLAY_UNVERIFIABLE=0,
    BBX_REPLAY_NO_MARKER=1,
    BBX_REPLAY_MATCHING_MARKER=2
} BBXReplayObservation;
static inline BBXReplayObservation bbx_reviewed_replay_observe(
    int directory,const char *nonce,const char *transactionId){
    if(directory<0||!bbx_reviewed_uuid4(nonce)||
       !bbx_reviewed_lowerhex(transactionId,64))
        return BBX_REPLAY_UNVERIFIABLE;
    struct stat dirStat={0};
    if(fstat(directory,&dirStat)!=0||!S_ISDIR(dirStat.st_mode)||
       dirStat.st_uid!=geteuid()||(dirStat.st_mode&077)!=0)
        return BBX_REPLAY_UNVERIFIABLE;
    char filename[60];
    const int length=snprintf(filename,sizeof(filename),"nonce-%s.spent",nonce);
    if(length<1||(size_t)length>=sizeof(filename))
        return BBX_REPLAY_UNVERIFIABLE;
    const int fd=openat(directory,filename,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return errno==ENOENT?BBX_REPLAY_NO_MARKER:BBX_REPLAY_UNVERIFIABLE;
    struct stat fileStat={0};
    char expected[112];
    const int n=snprintf(expected,sizeof(expected),"bbx-replay-v1\n%s\n",
                         transactionId);
    bool matching=n>0&&(size_t)n<sizeof(expected);
    matching=matching&&fstat(fd,&fileStat)==0&&S_ISREG(fileStat.st_mode)&&
        fileStat.st_nlink==1&&fileStat.st_uid==geteuid()&&
        (fileStat.st_mode&0777)==0600&&fileStat.st_size==(off_t)n;
    if(matching){
        char observed[112]={0};
        const ssize_t got=read(fd,observed,(size_t)n);
        matching=got==n&&memcmp(observed,expected,(size_t)n)==0;
        /* Ensure the marker was not concurrently modified while reading. */
        struct stat after={0};
        matching=matching&&fstat(fd,&after)==0&&
            after.st_size==fileStat.st_size&&
            after.st_ino==fileStat.st_ino;
    }
    if(close(fd)!=0)matching=false;
    return matching?BBX_REPLAY_MATCHING_MARKER:BBX_REPLAY_UNVERIFIABLE;
}

#endif
