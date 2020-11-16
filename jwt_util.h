#ifndef PAM_TACPLUS_JWT_UTILS_H
#define PAM_TACPLUS_JWT_UTILS_H

#include <stdlib.h>
#include <string.h>

#define JWT_DEFINITION_FILE      "/usr/share/rtbrick/tacplus/jwt_claims.json"
#define JWT_RBAC_RTB_CMDS_FILE   "/usr/share/rtbrick/tacplus/rbac_role_rtb_cmds.json"
#define JWT_SECRET_FILE          "/var/rtbrick/auth/secrets_jwks.json" 
#define JWT_RTB_CMDS_LEN         2048
#define LOGIN_USERNAME_LEN       100
#define LOGIN_USER_MAX_GROUPS    100
#define USER_GROUP_NAME_LEN      20
#define ROLE_DEFAULT_PRIORITY    100
#define ROLES_TOKEN_DELIMITER    " "
#define ROLES_DEFAULT_ROLE_NAME  "default"

const char* jwt_util_create_token(pam_handle_t *pamh);


#endif  /* PAM_TACPLUS_JWT_UTILS_H */
