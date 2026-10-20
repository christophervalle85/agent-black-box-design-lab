/*
 * Experimental fail-closed XPC peer requirement helper.
 *
 * This uses Apple's live peer-signature enforcement, not PID/UID metadata.
 * Dynamic symbol resolution lets older macOS releases reject unsupported
 * identity enforcement rather than silently downgrading to unverified XPC.
 *
 * A positive release acceptance also requires Apple Developer ID/Team ID
 * verification of BOTH artifacts and a worker-side host peer requirement.
 * Ad-hoc-signed binaries can demonstrate rejection, never trusted launch.
 */
#ifndef BBX_PEER_REQUIREMENT_GATE_H
#define BBX_PEER_REQUIREMENT_GATE_H
#include <xpc/xpc.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

static bool bbx_valid_signing_identifier(const char *identifier) {
    if(!identifier)return false;
    size_t n=0;
    bool dot=false,segment=true;
    for(;identifier[n] && n<127;n++) {
        unsigned char c=(unsigned char)identifier[n];
        if(c=='.') {
            if(segment)return false;
            segment=true;dot=true;
        }else {
            if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
                 (c>='0'&&c<='9')||c=='-'))return false;
            segment=false;
        }
    }
    return n>0 && n<127 && dot && !segment;
}

/* Must be called BEFORE xpc_connection_resume(), on the actual connection. */
static int bbx_install_same_team_peer_requirement(
    xpc_connection_t connection,const char *expectedIdentifier) {
    if(!connection || !bbx_valid_signing_identifier(expectedIdentifier))
        return -1;
    typedef int32_t (*set_peer_requirement_t)(xpc_connection_t,const char *);
    void *symbol=dlsym(RTLD_DEFAULT,
                       "xpc_connection_set_peer_team_identity_requirement");
    if(!symbol)return -2; /* Unsupported OS: fail closed, no UID fallback. */
    set_peer_requirement_t require_peer=NULL;
    /* Avoid forbidden ISO-C function/object-pointer casts. */
    if(sizeof(require_peer)!=sizeof(symbol))return -3;
    __builtin_memcpy(&require_peer,&symbol,sizeof(require_peer));
    return require_peer(connection,expectedIdentifier);
}
#endif
