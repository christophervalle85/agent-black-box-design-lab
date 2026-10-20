/*
 * Test-vector MAC verifier, NOT a production authorization transport.
 * Caller MUST independently provision a trustworthy secret: choosing the
 * key from stdin, argv, env or another caller-controlled channel gives NO
 * authentication of the issuing controller. No such provisioning exists yet.
 * The reservationMac line is authenticated metadata, NOT native proof of
 * durable reservation, and this codec has no persistent replay defense.
 */
#ifndef BBX_REVIEWED_TRANSACTION_AUTHORITY_H
#define BBX_REVIEWED_TRANSACTION_AUTHORITY_H
#include "ReviewedTransactionHandoff.h"
#include <CommonCrypto/CommonHMAC.h>

#define BBX_AUTH_KEY_BYTES 32
static inline bool bbx_read_authorized_review(
    FILE *source,const unsigned char *key,size_t keySize,
    BBXPreissuedReview *out){
    if(!source||!key||keySize!=BBX_AUTH_KEY_BYTES||!out)return false;
    char data[1024];
    size_t used=0;
    for(;;){
        const int next=fgetc(source);
        if(next==EOF)break;
        if(used>=sizeof(data)-1 ||
           (next!='\n'&&(next<0x20||next>0x7e)))return false;
        data[used++]=(char)next;
    }
    if(ferror(source)||!used)return false;
    data[used]='\0';
    char *reservation=strstr(data,"reservationMac=");
    if(!reservation || reservation==data)return false;
    const size_t baseLength=(size_t)(reservation-data);
    if(baseLength>=768)return false;
    char canonical[768];
    memcpy(canonical,data,baseLength);
    canonical[baseLength]='\0';
    BBXPreissuedReview review={0};
    if(!bbx_parse_preissued_review(canonical,baseLength,&review))
        return false;
    char *reservationHex=reservation+sizeof("reservationMac=")-1;
    if((size_t)(data+used-reservationHex)<65)return false;
    char reservationTag[65];
    memcpy(reservationTag,reservationHex,64);
    reservationTag[64]='\0';
    if(!bbx_reviewed_lowerhex(reservationTag,64) ||
       reservationHex[64]!='\n')return false;
    char *tagLine=reservationHex+65;
    /* Bounds-check before looking at a fixed prefix on truncated input. */
    const size_t prefix=sizeof("authorityMac=")-1;
    if((size_t)(data+used-tagLine)!=prefix+65 ||
       memcmp(tagLine,"authorityMac=",prefix)!=0)return false;
    char *tagHex=tagLine+prefix;
    if(tagHex[64]!='\n')return false;
    char supplied[65];
    memcpy(supplied,tagHex,64);
    supplied[64]='\0';
    if(!bbx_reviewed_lowerhex(supplied,64))return false;
    static const char domain[]="bbx-audited-handoff-auth-v1\n";
    const size_t signedLength=(size_t)(tagLine-data);
    CCHmacContext mac={0};
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmacInit(&mac,kCCHmacAlgSHA256,key,keySize);
    CCHmacUpdate(&mac,domain,sizeof(domain)-1);
    CCHmacUpdate(&mac,data,signedLength);
    CCHmacFinal(&mac,digest);
    static const char alphabet[]="0123456789abcdef";
    char expected[65];
    for(size_t i=0;i<sizeof(digest);i++){
        expected[2*i]=alphabet[digest[i]>>4];
        expected[2*i+1]=alphabet[digest[i]&15];
    }
    expected[64]='\0';
    const bool authorized=bbx_reviewed_equal_hash(expected,supplied);
    if(!authorized)return false;
    *out=review;
    return true;
}
#endif
