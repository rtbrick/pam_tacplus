#ifndef PAM_TACPLUS_JWT_UTILS_H
#define PAM_TACPLUS_JWT_UTILS_H

#include <stdlib.h>
#include <string.h>

#define JWT_DEFINITION_FILE    "/var/rtbrick/auth/jwt_claims.json" 
#define JWT_SECRET_FILE        "/var/rtbrick/auth/secrets_jwks.json" 

char* jwt_create_token(pam_handle_t *pamh);


#endif  /* PAM_TACPLUS_JWT_UTILS_H */
