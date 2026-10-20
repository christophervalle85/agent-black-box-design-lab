/* Native-only offline HMAC audit verification test; no Keychain or Touch ID. */
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>
#include "ControllerAuditVerifier.h"
int main(int argc,const char *argv[]){
    @autoreleasepool {
        if(argc!=3||(strcmp(argv[1],"valid")!=0&&
                      strcmp(argv[1],"invalid")!=0))return 90;
        char input[960]={0};
        size_t used=0;
        int c=0;
        while((c=fgetc(stdin))!=EOF){
            if(used>=sizeof(input)-1||(c!='\n'&&(c<0x20||c>0x7e)))
                return 87;
            input[used++]=(char)c;
        }
        char *suffix=strstr(input,"reservationMac=");
        if(!suffix||suffix==input||used-(size_t)(suffix-input)!=
           sizeof("reservationMac=")-1+64+1)return 87;
        if(suffix[sizeof("reservationMac=")-1+64]!='\n')return 87;
        char claim[65]={0};
        memcpy(claim,suffix+sizeof("reservationMac=")-1,64);
        const size_t length=(size_t)(suffix-input);
        if(length>=768)return 87;
        input[length]='\0';
        BBXPreissuedReview review={0};
        if(!bbx_parse_preissued_review(input,length,&review))return 87;
        const BOOL success=bbx_test_verify_native_audit(argv[2],&review,claim);
        if((success?1:0)!=(strcmp(argv[1],"valid")==0))return 87;
        puts(success?"BBX_NATIVE_AUDIT_RESERVATION_VERIFIED":
                     "BBX_NATIVE_AUDIT_RESERVATION_DENIED");
        return 0;
    }
}
