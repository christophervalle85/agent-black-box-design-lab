/*
 * Apple CI-only, public-keyed deterministic HMAC verifier test.
 * This public fixture key is NOT an authorization secret.
 * Never link this vector or key into the signed native handoff host.
 */
#include "ReviewedTransactionAuthority.h"
#include <stdio.h>
#include <string.h>
static const unsigned char publicFixtureKey[32]={
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,
    0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f
};
int main(int argc,char **argv){
    if(argc!=2||(strcmp(argv[1],"valid")!=0 &&
                 strcmp(argv[1],"invalid")!=0))return 90;
    BBXPreissuedReview review={0};
    const bool valid=bbx_read_authorized_review(stdin,
        publicFixtureKey,sizeof(publicFixtureKey),&review);
    if(valid!=(strcmp(argv[1],"valid")==0))return 87;
    if(valid && (strcmp(review.reviewId,
                       "123e4567-e89b-42d3-a456-426614174000")!=0 ||
                 review.byteLength!=39 ||
                 review.issuedAt!=INT64_C(1790000000000) ||
                 review.expiresAt!=INT64_C(1790000060000)))return 88;
    puts(valid?"BBX_AUTH_MAC_NATIVE_VECTOR_VALID":
               "BBX_AUTH_MAC_NATIVE_VECTOR_REJECTED");
    return 0;
}
