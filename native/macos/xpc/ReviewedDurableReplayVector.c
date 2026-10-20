/* Separate native-process durable nonce receipt test; no XPC/UI/user files. */
#include "ReviewedDurableReplay.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char **argv){
    if(argc!=3)return 90;
    const int dir=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0)return 89;
    const char *nonce="abcdef12-3456-4789-8abc-123456789abc";
    const char *id="d70d0604dcbb4e5b9fe029784317e675"
                   "131d71a20123456789abcdefabcdef01";
    /* Both IDs are valid lowercase 64-digit hex. */
    BBXReplayDecision expected;
    BBXReplayDecision observed;
    if(strcmp(argv[1],"observe-empty")==0 ||
       strcmp(argv[1],"observe-spent")==0 ||
       strcmp(argv[1],"observe-foreign")==0 ||
       strcmp(argv[1],"observe-bad-id")==0 ||
       strcmp(argv[1],"observe-loose-dir")==0 ||
       strcmp(argv[1],"observe-symlink")==0 ||
       strcmp(argv[1],"observe-corrupt")==0){
        const bool empty=strcmp(argv[1],"observe-empty")==0;
        const bool foreign=strcmp(argv[1],"observe-foreign")==0;
        const bool bad=strcmp(argv[1],"observe-bad-id")==0;
        const bool loose=strcmp(argv[1],"observe-loose-dir")==0;
        const bool symlink=strcmp(argv[1],"observe-symlink")==0;
        const bool corrupt=strcmp(argv[1],"observe-corrupt")==0;
        const BBXReplayObservation want=empty?
            BBX_REPLAY_NO_MARKER:
            foreign||bad||loose||symlink||corrupt?
            BBX_REPLAY_UNVERIFIABLE:BBX_REPLAY_MATCHING_MARKER;
        const BBXReplayObservation found=bbx_reviewed_replay_observe(
            dir,symlink?"00000000-0000-4000-8000-000000000000":nonce,
            bad?"invalid":
            foreign?"ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff":id);
        if(close(dir)!=0||found!=want)return 87;
        puts(found==BBX_REPLAY_NO_MARKER?"BBX_OBSERVE_NO_MARKER":
             found==BBX_REPLAY_MATCHING_MARKER?"BBX_OBSERVE_MATCHING_MARKER":
             "BBX_OBSERVE_UNVERIFIABLE");
        return 0;
    }
    if(strcmp(argv[1],"fresh")==0){
        expected=BBX_REPLAY_FRESH_COMMITTED;
        observed=bbx_reviewed_replay_reserve(dir,nonce,id);
    }else if(strcmp(argv[1],"replay")==0){
        expected=BBX_REPLAY_ALREADY_SPENT;
        observed=bbx_reviewed_replay_reserve(dir,nonce,id);
    }else if(strcmp(argv[1],"other-id")==0){
        expected=BBX_REPLAY_ALREADY_SPENT;
        observed=bbx_reviewed_replay_reserve(dir,nonce,
                 "ffffffffffffffffffffffffffffffff"
                 "ffffffffffffffffffffffffffffffff");
    }else if(strcmp(argv[1],"bad-nonce")==0){
        expected=BBX_REPLAY_STORE_DENIED;
        observed=bbx_reviewed_replay_reserve(dir,
                 "arbitrary-host-path",id);
    }else if(strcmp(argv[1],"bad-id")==0){
        expected=BBX_REPLAY_STORE_DENIED;
        observed=bbx_reviewed_replay_reserve(dir,nonce,"forged");
    }else if(strcmp(argv[1],"loose-dir")==0){
        expected=BBX_REPLAY_STORE_DENIED;
        observed=bbx_reviewed_replay_reserve(dir,nonce,id);
    }else if(strcmp(argv[1],"symlink-marker")==0){
        expected=BBX_REPLAY_ALREADY_SPENT;
        observed=bbx_reviewed_replay_reserve(dir,
                 "00000000-0000-4000-8000-000000000000",id);
    }else if(strcmp(argv[1],"race")==0){
        observed=bbx_reviewed_replay_reserve(dir,
                 "123e4567-e89b-42d3-a456-426614174000",id);
        if(close(dir)!=0 || (observed!=BBX_REPLAY_FRESH_COMMITTED &&
                             observed!=BBX_REPLAY_ALREADY_SPENT))return 87;
        puts(observed==BBX_REPLAY_FRESH_COMMITTED
            ?"BBX_DURABLE_NATIVE_FRESH":"BBX_DURABLE_NATIVE_REPLAY");
        return 0;
    }else{
        close(dir);return 90;
    }
    if(close(dir)!=0 || observed!=expected)return 87;
    puts(observed==BBX_REPLAY_FRESH_COMMITTED
        ?"BBX_DURABLE_NATIVE_FRESH":
         observed==BBX_REPLAY_ALREADY_SPENT
        ?"BBX_DURABLE_NATIVE_REPLAY":
         "BBX_DURABLE_NATIVE_DENIED");
    return 0;
}
