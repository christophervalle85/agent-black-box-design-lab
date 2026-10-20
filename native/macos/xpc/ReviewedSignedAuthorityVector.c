/* Offline TEST verifier. Pin compiled before native binary signing, not from wire. */
#include "ReviewedTransactionSignedAuthority.h"
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv){
    if(argc!=2||(strcmp(argv[1],"valid")!=0&&
                  strcmp(argv[1],"invalid")!=0))return 90;
    BBXPreissuedReview review={0};
    const bool valid=bbx_read_signed_preissued_review(stdin,&review);
    if(valid!=(strcmp(argv[1],"valid")==0))return 87;
    if(valid&&(strcmp(review.reviewId,
                      "123e4567-e89b-42d3-a456-426614174000")!=0||
               review.byteLength!=39||
               review.issuedAt!=INT64_C(1790000000000)||
               review.expiresAt!=INT64_C(1790000060000)))return 88;
    puts(valid?"BBX_RSA_PINNED_NATIVE_VALID":"BBX_RSA_PINNED_NATIVE_REJECTED");
    return 0;
}
