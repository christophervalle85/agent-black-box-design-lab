/*
 * EXPERIMENTAL stdin data envelope, not proof of controller authorization.
 * Accept exactly the Node canonical v1 ASCII transcript plus transactionId.
 * Used only by a separately compiled/signed native development test host.
 */
#ifndef BBX_REVIEWED_HANDOFF_H
#define BBX_REVIEWED_HANDOFF_H
#include "ReviewedTransactionContract.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

typedef struct {
    char reviewId[37];
    char nonce[37];
    char sha256[65];
    char transactionId[65];
    int64_t issuedAt;
    int64_t expiresAt;
    uint64_t byteLength;
} BBXPreissuedReview;

static inline bool bbx_handoff_literal(char **cursor,const char *literal){
    const size_t n=strlen(literal);
    if(strlen(*cursor)<n || strncmp(*cursor,literal,n)!=0)return false;
    *cursor+=n;
    return true;
}
static inline bool bbx_handoff_field(
    char **cursor,const char *prefix,char *out,size_t size){
    if(!bbx_handoff_literal(cursor,prefix))return false;
    char *end=strchr(*cursor,'\n');
    if(!end)return false;
    const size_t n=(size_t)(end-*cursor);
    if(n==0 || n>=size)return false;
    memcpy(out,*cursor,n);
    out[n]='\0';
    *cursor=end+1;
    return true;
}
static inline bool bbx_handoff_int(const char *text,int64_t *output){
    if(!text||text[0]<'0'||text[0]>'9')return false;
    if(text[0]=='0'&&text[1])return false;
    errno=0;
    char *end=NULL;
    const unsigned long long result=strtoull(text,&end,10);
    if(errno || !end || *end!='\0' || result>BBX_REVIEWED_SAFE_INT_MAX)
        return false;
    *output=(int64_t)result;
    return true;
}
/* Shared bounded decoder: authenticated envelope tests use it after MAC check. */
static inline bool bbx_parse_preissued_review(char *data,size_t used,BBXPreissuedReview *out){
    if(!data||!out||!used||used>=768||data[used]!='\0')return false;
    for(size_t i=0;i<used;i++){
        const unsigned char c=(unsigned char)data[i];
        if(c!='\n'&&(c<0x20||c>0x7e))return false;
    }
    char *position=data;
    if(!bbx_handoff_literal(&position,"bbx-reviewed-transaction-v1\n") ||
       !bbx_handoff_literal(&position,"version=1\n"))
        return false;
    BBXPreissuedReview review={0};
    char byteLength[24],issued[24],expires[24];
    if(!bbx_handoff_field(&position,"reviewId=",review.reviewId,sizeof(review.reviewId)) ||
       !bbx_handoff_literal(&position,"operation=import\n") ||
       !bbx_handoff_literal(&position,"noteName=bbx-test-reviewed.txt\n") ||
       !bbx_handoff_field(&position,"byteLength=",byteLength,sizeof(byteLength)) ||
       !bbx_handoff_field(&position,"sha256=",review.sha256,sizeof(review.sha256)) ||
       !bbx_handoff_field(&position,"nonce=",review.nonce,sizeof(review.nonce)) ||
       !bbx_handoff_field(&position,"issuedAt=",issued,sizeof(issued)) ||
       !bbx_handoff_field(&position,"expiresAt=",expires,sizeof(expires)) ||
       !bbx_handoff_field(&position,"transactionId=",review.transactionId,sizeof(review.transactionId)) ||
       *position!='\0')return false;
    int64_t size=0;
    if(!bbx_handoff_int(byteLength,&size) ||
       !bbx_handoff_int(issued,&review.issuedAt) ||
       !bbx_handoff_int(expires,&review.expiresAt) ||
       size<1 || size>BBX_REVIEWED_MAX_BYTES)return false;
    review.byteLength=(uint64_t)size;
    char expected[65];
    if(!bbx_reviewed_transaction_id(
         review.reviewId,"import","bbx-test-reviewed.txt",
         review.byteLength,review.sha256,review.nonce,
         review.issuedAt,review.expiresAt,expected) ||
       !bbx_reviewed_equal_hash(expected,review.transactionId))
        return false;
    *out=review;
    return true;
}
static inline bool bbx_read_preissued_review(FILE *source,BBXPreissuedReview *out){
    if(!source||!out)return false;
    char data[768];
    size_t used=0;
    for(;;){
        const int next=fgetc(source);
        if(next==EOF)break;
        if(used>=sizeof(data)-1 || (next!='\n'&&(next<0x20||next>0x7e)))
            return false;
        data[used++]=(char)next;
    }
    if(ferror(source)||!used)return false;
    data[used]='\0';
    return bbx_parse_preissued_review(data,used,out);
}
#endif
