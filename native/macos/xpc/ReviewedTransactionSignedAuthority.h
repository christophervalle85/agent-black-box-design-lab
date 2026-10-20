/*
 * TEST ONLY: independently pinned RSA-PSS/SHA256 review authentication.
 * BBXTestPinnedControllerKey.h is generated in a disposable build folder,
 * included BEFORE code signing, and is not transmitted in the stdin record.
 * No verified human approval, durable replay state or production trust exists.
 */
#ifndef BBX_REVIEWED_SIGNED_AUTHORITY_H
#define BBX_REVIEWED_SIGNED_AUTHORITY_H
#include "ReviewedTransactionHandoff.h"
#include <Security/Security.h>
#include "BBXTestPinnedControllerKey.h"

static inline bool bbx_signed_decode_hex(
    const char *text,unsigned char *bytes,size_t length){
    if(!text||!bytes)return false;
    for(size_t i=0;i<length;i++){
        unsigned value=0;
        for(size_t j=0;j<2;j++){
            const char ch=text[2*i+j];
            unsigned part;
            if(ch>='0'&&ch<='9')part=(unsigned)(ch-'0');
            else if(ch>='a'&&ch<='f')part=(unsigned)(ch-'a'+10);
            else return false;
            value=(value<<4)|part;
        }
        bytes[i]=(unsigned char)value;
    }
    return true;
}
static inline bool bbx_read_signed_preissued_review(
    FILE *source,BBXPreissuedReview *out){
    if(!source||!out)return false;
    char wire[1536];
    size_t used=0;
    for(;;){
        const int next=fgetc(source);
        if(next==EOF)break;
        if(used>=sizeof(wire)-1||
           (next!='\n'&&(next<0x20||next>0x7e)))return false;
        wire[used++]=(char)next;
    }
    if(ferror(source)||!used)return false;
    wire[used]='\0';
    char *reservation=strstr(wire,"reservationMac=");
    if(!reservation||reservation==wire)return false;
    const size_t baseLength=(size_t)(reservation-wire);
    if(baseLength>=768||wire[baseLength-1]!='\n')return false;
    const size_t resPrefix=sizeof("reservationMac=")-1;
    const size_t sigPrefix=sizeof("controllerSig=")-1;
    const size_t resLength=resPrefix+64+1;
    const size_t sigLength=sigPrefix+512+1;
    if((size_t)(wire+used-reservation)!=resLength+sigLength||
       reservation[resPrefix+64]!='\n')return false;
    char auditMac[65];
    memcpy(auditMac,reservation+resPrefix,64);
    auditMac[64]='\0';
    if(!bbx_reviewed_lowerhex(auditMac,64))return false;
    const char *tag=reservation+resLength;
    if(memcmp(tag,"controllerSig=",sigPrefix)!=0||
       tag[sigPrefix+512]!='\n')return false;
    unsigned char signature[256];
    if(!bbx_signed_decode_hex(tag+sigPrefix,signature,sizeof(signature)))
        return false;
    static const char domain[]="bbx-reviewed-controller-rsa-pss-v1\n";
    const size_t payloadLength=(size_t)(tag-wire);
    unsigned char messageBuffer[1536];
    if(sizeof(domain)-1+payloadLength>sizeof(messageBuffer))
        return false;
    memcpy(messageBuffer,domain,sizeof(domain)-1);
    memcpy(messageBuffer+sizeof(domain)-1,wire,payloadLength);

    bool verified=false;
    CFDataRef keyData=CFDataCreate(kCFAllocatorDefault,
        bbx_test_pinned_rsa_der,(CFIndex)sizeof(bbx_test_pinned_rsa_der));
    const void *attrKeys[]={kSecAttrKeyType,kSecAttrKeyClass};
    const void *attrValues[]={kSecAttrKeyTypeRSA,kSecAttrKeyClassPublic};
    CFDictionaryRef attrs=CFDictionaryCreate(kCFAllocatorDefault,
        attrKeys,attrValues,2,&kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if(!keyData||!attrs)goto cleanup;
    SecKeyRef publicKey=SecKeyCreateWithData(keyData,attrs,NULL);
    if(!publicKey)goto cleanup;
    CFDataRef message=CFDataCreate(kCFAllocatorDefault,messageBuffer,
        (CFIndex)(sizeof(domain)-1+payloadLength));
    CFDataRef sig=CFDataCreate(kCFAllocatorDefault,signature,
        (CFIndex)sizeof(signature));
    if(message&&sig&&
       SecKeyIsAlgorithmSupported(publicKey,kSecKeyOperationTypeVerify,
                                 kSecKeyAlgorithmRSASignatureMessagePSSSHA256))
        verified=SecKeyVerifySignature(publicKey,
            kSecKeyAlgorithmRSASignatureMessagePSSSHA256,message,sig,NULL);
    if(sig)CFRelease(sig);
    if(message)CFRelease(message);
    CFRelease(publicKey);
cleanup:
    if(attrs)CFRelease(attrs);
    if(keyData)CFRelease(keyData);
    if(!verified)return false;
    char canonical[768];
    memcpy(canonical,wire,baseLength);
    canonical[baseLength]='\0';
    BBXPreissuedReview review={0};
    if(!bbx_parse_preissued_review(canonical,baseLength,&review))return false;
    *out=review;
    return true;
}
#endif
