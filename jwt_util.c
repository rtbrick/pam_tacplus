#include "pam_tacplus.h"
#include "support.h"
#include "jwt_util.h"

#include <stdlib.h>
#include <string.h>
#include <json-parser/json.h>
#include <cjose/jws.h>
#include <cjose/header.h>
#include <time.h>
#include <json-builder.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum jwt_rtb_cmd_type_t {
    JWT_RTB_CMD_ALLOW = 0,
    JWT_RTB_CMD_DENY,
    JWT_RTB_CMD_MAX

} jwt_rtb_cmd_type;

/* For secure-management. This pointer caches JWK*/
static char *g_cmd_secret_jwk = NULL;

json_value*
json_parse_file (const char *file_name)
{
    FILE *fp;
    struct stat filestatus;
    int file_size;
    char* file_contents;
    json_char* json;
    json_value *value;
    json_settings settings = { 0 };
    settings.value_extra = json_builder_extra;  /* space for json-builder state */

    if (stat(file_name, &filestatus) != 0) {
        _pam_log(LOG_ERR, "JSON file not found %s: file: %s,function: %s, line: %ld",
                                    file_name, __FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }
    file_size = filestatus.st_size;
    file_contents = (char*)malloc(filestatus.st_size);
    if (!file_contents) {
        _pam_log(LOG_ERR, "Memory error: unable to allocate %d bytes: file: %s,function: %s, line: %ld",
                                    file_size, __FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }

    fp = fopen(file_name, "rt");
    if (!fp) {
        _pam_log(LOG_ERR, "Unable to open JWK file %s: file: %s,function: %s, line: %ld",
                                    file_name, __FILE__, __FUNCTION__, __LINE__);
        free(file_contents);
        return NULL;
    }
    if (fread(file_contents, file_size, 1, fp) != 1 ) {
        _pam_log(LOG_ERR, "Unable to read content of file %s: file: %s,function: %s, line: %ld",
                                    file_name, __FILE__, __FUNCTION__, __LINE__);
        fclose(fp);
        free(file_contents);
        return NULL;
    }
    fclose(fp);

    json = (json_char *)file_contents;
    value = json_parse_ex(&settings, json, file_size, 0);

    if (!value) {
        _pam_log(LOG_ERR, "Unable to parse file %s, not a valid JSON: file: %s,function: %s, line: %ld",
                                    file_name, __FILE__, __FUNCTION__, __LINE__);
        free(file_contents);
        return NULL;
    }
    free(file_contents);
    return value;
}

/* Reads and returns JWK from the specified secret file */

char *
get_secret_jwks(const char *key_filename)
{
    json_value  *file_json  = NULL,
                *keys       = NULL,
                *key        = NULL,
                *tmp        = NULL;
    uint32_t    length      = 0,
                idx         = 0;
    char       *secret      = NULL;

    if(!g_cmd_secret_jwk) {
        file_json = json_parse_file(key_filename);
        if(!file_json) {
            return NULL;
        }
        keys = json_get(file_json, json_array, "keys");
        if(!keys) {
            _pam_log(LOG_ERR, "Failed to read keys from JWK file %s: file: %s,function: %s, line: %ld",
                                    key_filename, __FILE__, __FUNCTION__, __LINE__);
            return NULL;
        }

        length = JSON_ARRAY_LEN(keys);
        if (length > 1) {
            _pam_log(LOG_ERR, "Multiple keys in JWK secret file %s: file: %s,function: %s, line: %ld",
                                    key_filename, __FILE__, __FUNCTION__, __LINE__);
        }
        key = JSON_ARRAY(keys, idx);
        tmp = key->parent;   /* Backup of the parent node pointer*/
        key->parent = NULL;  /* Unlinking the parent node since json-builder builds
                parent as well which is not needed in this case*/
        secret = (char*)malloc(json_measure(key)+1);
        json_serialize(secret, key);
        key->parent = tmp;  /* Linking the key's parent node again*/
        g_cmd_secret_jwk = secret;
        free(file_json);   /* Free the parsed json_value pointer*/
    }
    return g_cmd_secret_jwk;
}

const char *
create_jwt(cjose_header_t *hdr, const char *key, const char *plain){

    cjose_err err;
    char *token=NULL;
    cjose_jwk_t *jwk = cjose_jwk_import(key, strlen(key), &err);
    if(!jwk){
        _pam_log(LOG_ERR, "Failed to import JSON Web Key from given key: file: %s,function: %s, line: %ld",
                                    __FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }

    // create the JWE
    size_t plain_len = strlen(plain);
    cjose_jws_t *jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
    if(!jws) {
        _pam_log(LOG_ERR, "Failed to sign header and plain: file: %s,function: %s, line: %ld",
                                    __FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }
    const char *compact = NULL;
    cjose_jws_export(jws, &compact, &err);
    if(!compact){
        _pam_log(LOG_ERR, "Failed to export JWS to base64url token: file: %s,function: %s, line: %ld",
                                    __FILE__, __FUNCTION__, __LINE__);
        return NULL;
    }
    return compact;
}

void jwt_set_header(cjose_header_t *hdr, json_value* value)
{
        int length, x;
        cjose_err err;
        if (value == NULL) {
            _pam_log(LOG_ERR, "JSON object is NULL: file: %s,function: %s, line: %ld", __FILE__, __FUNCTION__, __LINE__);
            return;
        } 
        length = value->u.object.length;
        for (x = 0; x < length; x++) {

            switch((value->u.object.values[x].value)->type) 
            {
                case json_none:
                case json_integer:
                case json_object:
                case json_double:
                case json_array:
                case json_boolean:
                        _pam_log(LOG_ERR, "Invalid claim, header supports only string type file: %s,function: %s, line: %ld",
                                                    __FILE__, __FUNCTION__, __LINE__);
                        break;
                case json_string:
                        if(!cjose_header_set(hdr, value->u.object.values[x].name, (value->u.object.values[x].value)->u.string.ptr, &err))
                        {
                            _pam_log(LOG_ERR, "Failed to set header attribute %s: file: %s,function: %s, line: %ld",
                                    value->u.object.values[x].name,__FILE__, __FUNCTION__, __LINE__);
                        }
                        break;
            }
        }
}

cjose_header_t *
jwt_create_custom_header(pam_handle_t *pamh, json_value *header)
{
    /*
     * Customize header if needed
     */
    cjose_err err;
    json_value *tmp = NULL;

    // set header for JWE
    cjose_header_t *hdr = cjose_header_new(&err);
    if(!hdr) {
        _pam_log(LOG_ERR, "cjose_header_set failed");
        return NULL;
    }

    jwt_set_header(hdr, header);
    return hdr;
}

bool
jwt_set_role_default_cmds(const char *role_name, char *commands, uint8_t cmd_type) {

    json_value  *root = NULL,
                *role = NULL,
                *rtb_cmds = NULL;
    char        *delimiter = ";",
                *cmd = NULL;
    uint16_t    length,
                idx;
    bool        ret = true;

    root = json_parse_file(JWT_RBAC_RTB_CMDS_FILE);
    if(!root) {
        _pam_log(LOG_ERR, "token creation- Failed to parse rbac role cmds definition file : %s", JWT_RBAC_RTB_CMDS_FILE);
        return false;
    }
    role = json_get(root, json_object, role_name);
    if(!role) {
        _pam_log(LOG_ERR, "token creation- Failed to read (role : %s) field from json file %s", role_name, JWT_RBAC_RTB_CMDS_FILE);
        ret = false;
        goto done;
    }
    switch(cmd_type) {

        case JWT_RTB_CMD_ALLOW:
            rtb_cmds = json_get(role, json_array, "rtb-allow-cmds");
            if(!rtb_cmds) {
                _pam_log(LOG_ERR, "token creation- Failed to allow-cmds for role : %s field from json file %s", role_name, JWT_RBAC_RTB_CMDS_FILE);
                ret = false;
                goto done;
            }
            break;

        case JWT_RTB_CMD_DENY:
            rtb_cmds = json_get(role, json_array, "rtb-deny-cmds");
            if(!rtb_cmds) {
                _pam_log(LOG_ERR, "token creation- Failed to deny-cmds for role : %s field from json file %s", role_name, JWT_RBAC_RTB_CMDS_FILE);
                ret = false;
                goto done;
            }
            break;

        default:
            ret = false;
            goto done;
    }

    /* Populate commands buffer with list of commands delimited by ';' */
    length = JSON_ARRAY_LEN(rtb_cmds);
    if(length < 1) {
        ret = false;
        goto done;
    }
    for (idx = 0; idx < length; idx++) {

        cmd = JSON_ARRAY_STRING(rtb_cmds, idx);
        strcat(commands, cmd);
        strcat(commands, delimiter);
    }

done:
    /*Free read json value */
    json_value_free(root);
    return ret;

}

char *
jwt_get_serialized_custom_payload(pam_handle_t *pamh, json_value *payload)
{
    /*
     * Customize payload if needed
     */
    time_t      iat;
    char        *user                        = NULL,
                username[LOGIN_USERNAME_LEN] = {0},
                cmd[JWT_RTB_CMDS_LEN]        = {0}; /* Command buffer to store allow/deny commands */
    char        *plain                       = NULL;
    const char  *scope                       = NULL,
                *rtb_allow_cmds              = NULL,
                *rtb_deny_cmds               = NULL;
    json_value  *tmp                         = NULL,
                *jval                        = NULL;

    bool ret;

    /* Get token issue at time */
    iat = time(NULL);
    /* Get role from the pam handle */
    scope = pam_getenv(pamh, "ROLE");
  
    /* If role is not present the it role is the local user name*/
    if(!scope) {
        getlogin_r(username, LOGIN_USERNAME_LEN);
        if(strlen(username) < 1) {
            _pam_log(LOG_ERR, "token creation- Failed to get local username");
            return NULL;
        } else {
            scope = username;
        }
    }
    _pam_get_user(pamh, &user);

    tmp = json_object_new(1024);
    jval = json_integer_new(iat+9000);
    json_object_push_uniq(payload, "exp", jval);

    jval = json_integer_new(iat);
    json_object_push_uniq(payload, "iat", jval);

    jval = json_string_new(user);
    json_object_push_uniq(payload, "name", jval);
    /*sub claim JWT is username since it is unique per user*/
    json_object_push_uniq(payload, "sub", jval);

    jval = json_string_new(scope);
    json_object_push_uniq(payload, "scope", jval);

    rtb_allow_cmds = pam_getenv(pamh, "RTB_ALLOW_CMDS");
    if(!rtb_allow_cmds) {
        ret = jwt_set_role_default_cmds(scope, cmd, JWT_RTB_CMD_ALLOW);
        if (ret) {
            jval = json_string_new(cmd);
            json_object_push_uniq(payload, "rtb-allow-cmds", jval);
        } else{
            _pam_log(LOG_WARNING, "token creation- Failed to get allow cmds for role %s", scope);
        }
    } else{
        jval = json_string_new(rtb_allow_cmds);
        json_object_push_uniq(payload, "rtb-allow-cmds", jval);
    }

    /*Clear command buffer*/
    memset(cmd, 0, JWT_RTB_CMDS_LEN);

    rtb_deny_cmds= pam_getenv(pamh, "RTB_DENY_CMDS");
    if(!rtb_deny_cmds) {
        ret = jwt_set_role_default_cmds(scope, cmd, JWT_RTB_CMD_DENY);
        if (ret) {
            jval = json_string_new(cmd);
            json_object_push_uniq(payload, "rtb-deny-cmds", jval);
        } else{
            _pam_log(LOG_WARNING, "token creation- Failed to get deny cmds for role %s", scope);
        }
    } else {
        jval = json_string_new(rtb_deny_cmds);
        json_object_push_uniq(payload, "rtb-deny-cmds", jval);
    }

    plain = (char *) malloc(json_measure(payload));
    tmp = payload->parent;
    payload->parent = NULL;
    json_serialize(plain, payload);
    payload->parent = tmp;

    return plain;
}

/* Creates a JWT token based on the user parameters present in pam handle*/
const char *
jwt_create_token(pam_handle_t *pamh)
{
    char            *plain      = NULL;
    cjose_header_t  *hdr        = NULL;
    json_value      *root       = NULL,
                    *header     = NULL,
                    *payload    = NULL;

    /*Get the JWK secret file which is needed for signing token*/
    char *jwk = get_secret_jwks(JWT_SECRET_FILE);
    if(!jwk) {
        _pam_log(LOG_ERR, "token creation- Failed to get JWK file : %s", JWT_SECRET_FILE);
        return NULL;
    }
    /*Get the json handle for JWT definition template file */
    root = json_parse_file(JWT_DEFINITION_FILE);
    if(!root) {
        _pam_log(LOG_ERR, "token creation- Failed to parse token definition file : %s", JWT_DEFINITION_FILE);
        return NULL;
    }
    /*Get the header section from the JWT definition template file */
    header = json_get(root, json_object, "header");
    if(!header) {
        _pam_log(LOG_ERR, "token creation- Failed to read header attribute from json file %s", JWT_DEFINITION_FILE);
        return NULL;
    }
    /*Get the payload section from the JWT definition template file */
    payload = json_get(root, json_object, "payload");
    if(!payload) {
        _pam_log(LOG_ERR, "token creation- Failed to read payload attribute from json file %s", JWT_DEFINITION_FILE);
        return NULL;
    }

    /* Create the JWT based on the header and payload definition */
    hdr = jwt_create_custom_header(pamh, header);
    plain = jwt_get_serialized_custom_payload(pamh, payload);
    return create_jwt(hdr, jwk, plain);
}
