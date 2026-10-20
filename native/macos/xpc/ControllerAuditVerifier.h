/*
 * TEST ONLY: read-only independent native re-computation of Node's HMAC
 * audit history, anchored checkpoint and exact transaction reservation.
 *
 * Audit files and HMAC secret remain same-user/Node-managed: this catches
 * accidental, unauthenticated or stale handoffs, NOT a compromised Node
 * process that has the audit HMAC secret. Never call it independent trust
 * provisioning. The fixed directory comes from the signed local fixture
 * harness, not from XPC or a model-provided path.
 */
#ifndef BBX_TEST_CONTROLLER_AUDIT_VERIFIER_H
#define BBX_TEST_CONTROLLER_AUDIT_VERIFIER_H
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonHMAC.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "ReviewedTransactionHandoff.h"

static inline NSData *bbx_test_read_audit_member(int folder,const char *name,
                                               NSUInteger limit){
    if(folder<0||!name)return nil;
    const int fd=openat(folder,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return nil;
    struct stat st={0};
    BOOL valid=fstat(fd,&st)==0;
    /* Only mode 0600 is accepted, never group/world permissions. */
    valid=valid&&S_ISREG(st.st_mode)&&st.st_nlink==1&&
          st.st_uid==geteuid()&&(st.st_mode&0777)==0600&&
          st.st_size>=0&&(unsigned long long)st.st_size<=limit;
    NSMutableData *buffer=valid?
        [NSMutableData dataWithLength:(NSUInteger)st.st_size]:nil;
    if(buffer){
        size_t offset=0;
        while(offset<(size_t)st.st_size){
            const ssize_t n=read(fd,(char *)[buffer mutableBytes]+offset,
                                 (size_t)st.st_size-offset);
            if(n<=0){valid=NO;break;}
            offset+=(size_t)n;
        }
        unsigned char extra=0;
        if(valid&&read(fd,&extra,1)!=0)valid=NO;
    }
    if(close(fd)!=0)valid=NO;
    return valid?buffer:nil;
}
static inline NSArray *bbx_test_audit_lines(NSData *data){
    if(!data||[data length]==0)return nil;
    NSString *content=[[NSString alloc] initWithData:data
                                            encoding:NSUTF8StringEncoding];
    if(!content||![content hasSuffix:@"\n"])return nil;
    NSArray *all=[content componentsSeparatedByString:@"\n"];
    if([all count]<2||[all count]>1001||
       ![[all lastObject] isEqualToString:@""])return nil;
    return [all subarrayWithRange:NSMakeRange(0,[all count]-1)];
}
static inline BOOL bbx_test_audit_hex(NSString *text){
    if(![text isKindOfClass:[NSString class]]||[text length]!=64)return NO;
    return bbx_reviewed_lowerhex([text UTF8String],64);
}
static inline NSDictionary *bbx_test_json_object(NSString *line){
    NSData *data=[line dataUsingEncoding:NSUTF8StringEncoding];
    if(!data)return nil;
    id parsed=[NSJSONSerialization JSONObjectWithData:data
                                              options:0 error:nil];
    return [parsed isKindOfClass:[NSDictionary class]]?parsed:nil;
}
static inline NSString *bbx_test_json_quoted_raw(NSString *raw){
    /* Node's JSON.stringify(raw) escapes ASCII quotation, backslash and
       control bytes. All synthetic audit events are ASCII printable. */
    const char *input=[raw UTF8String];
    if(!input)return nil;
    NSMutableString *escaped=[NSMutableString string];
    for(const unsigned char *p=(const unsigned char *)input;*p;p++){
        if(*p<0x20||*p>0x7e)return nil;
        if(*p=='"'||*p=='\\')[escaped appendString:@"\\"];
        [escaped appendFormat:@"%c",*p];
    }
    return escaped;
}
static inline BOOL bbx_test_verify_native_audit(
    const char *directory,const BBXPreissuedReview *review,
    const char *reservationMac){
    if(!directory||directory[0]!='/'||strnlen(directory,4096)>=4096||
       !review||!bbx_reviewed_uuid4(review->nonce)||
       !bbx_reviewed_lowerhex(reservationMac,64))return NO;
    const int folder=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(folder<0)return NO;
    struct stat st={0};
    BOOL safe=fstat(folder,&st)==0&&S_ISDIR(st.st_mode)&&
        st.st_uid==geteuid()&&(st.st_mode&0777)==0700;
    NSData *rows=safe?bbx_test_read_audit_member(folder,
        "handoff-audit.jsonl",256*1024):nil;
    NSData *macs=safe?bbx_test_read_audit_member(folder,
        "handoff-audit.jsonl.mac.jsonl",256*1024):nil;
    NSData *secret=safe?bbx_test_read_audit_member(folder,
        "handoff-audit.jsonl.hmac.key",128):nil;
    NSData *anchor=safe?bbx_test_read_audit_member(folder,
        "handoff-audit.jsonl.anchor.json",1024):nil;
    if(close(folder)!=0)return NO;
    if(!rows||!macs||!secret||!anchor)return NO;
    NSArray *events=bbx_test_audit_lines(rows);
    NSArray *signatures=bbx_test_audit_lines(macs);
    if(!events||!signatures||[events count]!=[signatures count]||
       [events count]<4)return NO;
    NSString *keyHex=[[NSString alloc] initWithData:secret
                                           encoding:NSASCIIStringEncoding];
    if([keyHex length]!=65||![keyHex hasSuffix:@"\n"])return NO;
    keyHex=[keyHex substringToIndex:64];
    if(!bbx_test_audit_hex(keyHex))return NO;
    unsigned char key[32];
    const char *keyStr=[keyHex UTF8String];
    for(int i=0;i<32;i++){
        unsigned v=0;
        if(sscanf(keyStr+2*i,"%2x",&v)!=1)return NO;
        key[i]=(unsigned char)v;
    }
    NSString *previous=[@"" stringByPaddingToLength:64
                                         withString:@"0" startingAtIndex:0];
    NSString *lastRule=nil;
    NSUInteger lifecycle=0;
    for(NSUInteger i=0;i<[events count];i++){
        NSString *raw=events[i];
        NSDictionary *event=bbx_test_json_object(raw);
        NSDictionary *mac=bbx_test_json_object(signatures[i]);
        if(!event||!mac||[mac count]!=3||
           ![mac[@"seq"] isKindOfClass:[NSNumber class]]||
           [mac[@"seq"] unsignedIntegerValue]!=i+1||
           ![mac[@"prev"] isKindOfClass:[NSString class]]||
           ![mac[@"prev"] isEqualToString:previous]||
           !bbx_test_audit_hex(mac[@"mac"]))return NO;
        NSString *quoted=bbx_test_json_quoted_raw(raw);
        if(!quoted)return NO;
        NSString *canonical=[NSString stringWithFormat:
            @"{\"version\":1,\"seq\":%lu,\"prev\":\"%@\",\"raw\":\"%@\"}",
            (unsigned long)(i+1),previous,quoted];
        NSData *bytes=[canonical dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char digest[32]={0};
        CCHmac(kCCHmacAlgSHA256,key,32,[bytes bytes],[bytes length],digest);
        char hex[65]={0};
        const char digits[]="0123456789abcdef";
        for(int n=0;n<32;n++){
            hex[2*n]=digits[digest[n]>>4];
            hex[2*n+1]=digits[digest[n]&15];
        }
        NSString *expected=[NSString stringWithUTF8String:hex];
        if(![expected isEqualToString:mac[@"mac"]])return NO;
        previous=expected;
        lastRule=event[@"ruleId"];
        if(![lastRule isKindOfClass:[NSString class]])return NO;
        NSString *approval=event[@"approvalId"];
        if(![approval isKindOfClass:[NSString class]])return NO;
        if(![approval isEqualToString:
             [NSString stringWithUTF8String:review->reviewId]])continue;
        NSString *source=event[@"source"];
        if(![source isKindOfClass:[NSString class]]||
           ![source isEqualToString:@"mac-transfer-synthetic"])return NO;
        if([lastRule isEqualToString:@"MAC_TRANSFER_REVIEW"]){
            if(lifecycle!=0)return NO;
            lifecycle=1;
        }else if([lastRule isEqualToString:@"MAC_TRANSFER_APPROVED"]){
            if(lifecycle!=1)return NO;
            lifecycle=2;
        }else if([lastRule isEqualToString:@"MAC_TRANSFER_DISPATCH_ATTEMPT"]){
            if(lifecycle!=2)return NO;
            lifecycle=3;
        }else if([lastRule isEqualToString:@"MAC_TRANSFER_DISPATCH_RESERVED"]){
            if(lifecycle!=3||i!=[events count]-1)return NO;
            if(![event[@"transferTransactionId"] isKindOfClass:[NSString class]]||
               ![event[@"transferNonce"] isKindOfClass:[NSString class]]||
               ![event[@"transferSHA256"] isKindOfClass:[NSString class]]||
               ![event[@"transferTransactionId"]
                  isEqualToString:[NSString stringWithUTF8String:
                    review->transactionId]]||
               ![event[@"transferNonce"]
                  isEqualToString:[NSString stringWithUTF8String:
                    review->nonce]]||
               ![event[@"transferSHA256"]
                  isEqualToString:[NSString stringWithUTF8String:
                    review->sha256]]||
               ![event[@"transferBytes"] isKindOfClass:[NSNumber class]]||
               [event[@"transferBytes"] unsignedLongLongValue]!=review->byteLength||
               ![event[@"transferExpiresAt"] isKindOfClass:[NSNumber class]]||
               [event[@"transferExpiresAt"] longLongValue]!=review->expiresAt)
                return NO;
            lifecycle=4;
        }else if(lifecycle==4){
            // A terminal outcome or any later step invalidates this witness.
            return NO;
        }
    }
    NSDictionary *checkpoint=bbx_test_json_object(
        [[NSString alloc] initWithData:anchor encoding:NSUTF8StringEncoding]);
    if(!checkpoint||[checkpoint count]!=2||
       ![checkpoint[@"seq"] isKindOfClass:[NSNumber class]]||
       [checkpoint[@"seq"] unsignedIntegerValue]!=[events count]||
       ![checkpoint[@"mac"] isKindOfClass:[NSString class]]||
       ![checkpoint[@"mac"] isEqualToString:previous]||
       ![previous isEqualToString:
          [NSString stringWithUTF8String:reservationMac]]||
       lifecycle!=4||
       ![lastRule isEqualToString:@"MAC_TRANSFER_DISPATCH_RESERVED"])
        return NO;
    return YES;
}
#endif
