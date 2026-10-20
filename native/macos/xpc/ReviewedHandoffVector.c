/*
 * Test-only parser verifier for a public, deterministic synthetic contract.
 * No code signing, Touch ID, XPC or filesystem transfers are performed.
 * Exit zero ONLY if parser accepts valid mode or rejects invalid mode.
 */
#include "ReviewedTransactionHandoff.h"
#include <stdio.h>
#include <string.h>

int main(int argc,char *argv[]){
    if(argc!=2 || (strcmp(argv[1],"valid")!=0 &&
                   strcmp(argv[1],"invalid")!=0))return 90;
    BBXPreissuedReview review={0};
    const bool valid=bbx_read_preissued_review(stdin,&review);
    const bool expectingValid=strcmp(argv[1],"valid")==0;
    if(valid!=expectingValid)return 87;
    if(valid &&
       (!bbx_reviewed_uuid4(review.reviewId) ||
        !bbx_reviewed_uuid4(review.nonce) ||
        review.byteLength!=39 ||
        review.issuedAt!=INT64_C(1790000000000) ||
        review.expiresAt!=INT64_C(1790000060000)))
        return 88;
    puts(valid?"BBX_HANDOFF_CODEC_NATIVE_VALID":
               "BBX_HANDOFF_CODEC_NATIVE_REJECTED");
    return 0;
}
