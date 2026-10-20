/*
 * Phase 6 test-only canonical data identity shared by native host/worker and
 * src/macos-reviewed-transaction.mjs. SHA-256 is NOT a signature, authenticated
 * approval, replay-resilient grant or proof of Touch ID decision.
 * No runtime file access or XPC connection is provided by this header.
 */
#ifndef BBX_REVIEWED_TRANSACTION_CONTRACT_H
#define BBX_REVIEWED_TRANSACTION_CONTRACT_H
#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#define BBX_REVIEWED_VERSION 1
#define BBX_REVIEWED_LIFETIME_MS 60000
#define BBX_REVIEWED_MAX_BYTES 2000
#define BBX_REVIEWED_SAFE_INT_MAX INT64_C(9007199254740991)
static inline bool bbx_reviewed_uuid4(const char *text){
    if(!text || strnlen(text,38)!=36)return false;
    for(size_t i=0;i<36;i++){
        if(i==8||i==13||i==18||i==23){
            if(text[i]!='-')return false;
        }else{
            const char c=text[i];
            if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
        }
    }
    return text[14]=='4' && strchr("89ab",text[19])!=NULL;
}
static inline bool bbx_reviewed_lowerhex(const char *text,size_t length){
    if(!text||strnlen(text,length+1)!=length)return false;
    for(size_t i=0;i<length;i++){
        if(!((text[i]>='0'&&text[i]<='9')||
             (text[i]>='a'&&text[i]<='f')))return false;
    }
    return true;
}
static inline bool bbx_reviewed_name(const char *name){
    if(!name)return false;
    const size_t n=strnlen(name,65);
    if(n<14||n>64||strncmp(name,"bbx-test-",9)!=0 ||
       strcmp(name+n-4,".txt")!=0)return false;
    for(size_t i=9;i<n-4;i++){
        const char c=name[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='_'||c=='-'))return false;
    }
    return true;
}
/* The native and Node transcripts MUST be byte-for-byte identical. */
static inline bool bbx_reviewed_transaction_id(
    const char *reviewId,const char *operation,const char *noteName,
    uint64_t byteLength,const char *sha256,const char *nonce,
    int64_t issuedAt,int64_t expiresAt,char out[65]){
    if(!out || !bbx_reviewed_uuid4(reviewId) ||
       !bbx_reviewed_uuid4(nonce) ||
       !operation || (strcmp(operation,"import")!=0 &&
                      strcmp(operation,"export")!=0) ||
       !bbx_reviewed_name(noteName) ||
       byteLength<1 || byteLength>BBX_REVIEWED_MAX_BYTES ||
       !bbx_reviewed_lowerhex(sha256,64) ||
       issuedAt<0 || issuedAt>BBX_REVIEWED_SAFE_INT_MAX-BBX_REVIEWED_LIFETIME_MS ||
       expiresAt!=issuedAt+BBX_REVIEWED_LIFETIME_MS)
        return false;
    char canonical[650];
    const int count=snprintf(canonical,sizeof(canonical),
        "bbx-reviewed-transaction-v1\n"
        "version=1\n"
        "reviewId=%s\n"
        "operation=%s\n"
        "noteName=%s\n"
        "byteLength=%" PRIu64 "\n"
        "sha256=%s\n"
        "nonce=%s\n"
        "issuedAt=%" PRId64 "\n"
        "expiresAt=%" PRId64 "\n",
        reviewId,operation,noteName,byteLength,sha256,nonce,issuedAt,expiresAt);
    if(count<=0||(size_t)count>=sizeof(canonical))return false;
    unsigned char raw[CC_SHA256_DIGEST_LENGTH];
    if(!CC_SHA256(canonical,(CC_LONG)count,raw))return false;
    const char alphabet[]="0123456789abcdef";
    for(size_t i=0;i<sizeof(raw);i++){
        out[2*i]=alphabet[raw[i]>>4];
        out[2*i+1]=alphabet[raw[i]&15];
    }
    out[64]='\0';
    return true;
}
/* Constant-time-ish digest comparison for known fixed-length strings. */
static inline bool bbx_reviewed_equal_hash(const char *first,const char *second){
    if(!bbx_reviewed_lowerhex(first,64) ||
       !bbx_reviewed_lowerhex(second,64))return false;
    unsigned difference=0;
    for(size_t i=0;i<64;i++)difference|=(unsigned char)first[i]^(unsigned char)second[i];
    return difference==0;
}
#endif
