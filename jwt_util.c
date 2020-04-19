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


/* For secure-management. This pointer caches JWK*/
static char *g_cmd_secret_jwk = NULL;

json_value*
jwt_parse_file (const char *file_name)
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

char *
get_secret_jwks(const char *key_filename)
{
    json_value  *file_json= NULL,
                *keys=NULL,
                *key = NULL,
                *tmp = NULL;
    uint32_t    length = 0,
                idx = 0;
    char       *secret = NULL;

    if(!g_cmd_secret_jwk) {
        file_json = jwt_parse_file(key_filename);
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

char *
jwt_get_serialized_custom_payload(pam_handle_t *pamh, json_value *payload)
{
    /*
     * Customize payload if needed
     */
    time_t iat;
    char *user = NULL,
         username[LOGIN_USERNAME_LEN];
    char *scope = NULL,
         *plain=NULL;
    json_value *tmp=NULL,
               *jval = NULL;

    iat = time(NULL);
    scope = pam_getenv(pamh, "ROLE");
  
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

    jval = json_string_new(scope);
    json_object_push_uniq(payload, "scope", jval);

    plain = (char *) malloc(json_measure(payload));
    tmp = payload->parent;
    payload->parent = NULL;
    json_serialize(plain, payload);
    payload->parent = tmp;

    return plain;
}

char *
jwt_create_token(pam_handle_t *pamh)
{
    char *plain = NULL;
    cjose_header_t *hdr = NULL;
    json_value  *root = NULL,
                *header=NULL,
                *payload=NULL;

    char *jwk = get_secret_jwks(JWT_SECRET_FILE);
    if(!jwk) {
        _pam_log(LOG_ERR, "token creation- Failed to get JWK file : %s", JWT_SECRET_FILE);
        return NULL;
    }
    root = jwt_parse_file(JWT_DEFINITION_FILE);
    if(!root) {
        _pam_log(LOG_ERR, "token creation- Failed to parse token definition file : %s", JWT_DEFINITION_FILE);
        return NULL;
    }
    header = json_get(root, json_object, "header");
    if(!header) {
        _pam_log(LOG_ERR, "token creation- Failed to read header attribute from json file %s", JWT_DEFINITION_FILE);
        return NULL;
    }
    payload = json_get(root, json_object, "payload");
    if(!payload) {
        _pam_log(LOG_ERR, "token creation- Failed to read payload attribute from json file %s", JWT_DEFINITION_FILE);
        return NULL;
    }

    hdr = jwt_create_custom_header(pamh, header);
    plain = jwt_get_serialized_custom_payload(pamh, payload);

    return create_jwt(hdr, jwk, plain);
}
