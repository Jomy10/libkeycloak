#ifndef _KEYCLOAK_JSON_H
#define _KEYCLOAK_JSON_H

#include <stdbool.h>

#define _JSON_PARSEFN(json, jsonstr, err, exec) \
  cJSON* json = cJSON_Parse(jsonstr); \
  if (json == NULL) { \
    err.errcode = KeycloakE_JSON_Parse; \
    err.data.str = (char*) cJSON_GetErrorPtr(); \
    exec; \
  }

#define _JSON_PARSE_GOTO(json, jsonstr, err, gt) _JSON_PARSEFN(json, jsonstr, err, ({ goto gt; }))

/// Parse to a variable called `json`
#define _JSON_PARSE(json, jsonstr, err) _JSON_PARSEFN(json, jsonstr, err, ({ return err; }))

#define _JSON_GET_STRING_VALUE(json, field, err, gt) _JSON_GET_STRING_VALUE_VAR(json, field, #field, err, gt)

/// Loads a field with the name 'field' into a varable `field`.
/// If any error occured, written to err
#define _JSON_GET_STRING_VALUE_VAR(json, field_var, field, err, gt) \
  cJSON* field_var = cJSON_GetObjectItemCaseSensitive(json, field); \
  if (!cJSON_IsString(field_var) || (field_var->valuestring == NULL)) { \
    err.errcode = KeycloakE_JSON_Field; \
    err.data.str = field".string"; \
    goto gt ; \
  }

#define _JSON_GET_NUMBER_VALUE(json, field, err, gt) _JSON_GET_NUMBER_VALUE_VAR(json, field, #field, err, gt)

#define _JSON_GET_NUMBER_VALUE_VAR(json, field_var, field, err, gt) \
  cJSON* field_var = cJSON_GetObjectItemCaseSensitive(json, field); \
  if (!cJSON_IsNumber(field_var)) { \
    err.errcode = KeycloakE_JSON_Field; \
    err.data.str = field".number"; \
    goto gt; \
  }

#define _JSON_GET_OBJECT_VALUE(json, field, err, gt) _JSON_GET_OBJECT_VALUE_VAR(json, field, #field, err, gt)

#define _JSON_GET_OBJECT_VALUE_VAR(json, field_var, field, err, gt) \
  cJSON* field_var = cJSON_GetObjectItemCaseSensitive(json, field); \
  if (!cJSON_IsObject(field_var) || credentials->child == NULL) { \
    err.errcode = KeycloakE_JSON_Field; \
    err.data.str = field".object"; \
    goto gt; \
  }
  // TODO: add "or has no children to error message"

#define _JSON_GET_BOOL_VALUE(json, field, err, gt) _JSON_GET_BOOL_VALUE_VAR(json, field, #field, err, gt)

#define _JSON_GET_BOOL_VALUE_VAR(json, field_var, field, err, gt) \
  cJSON* _json_field_var = cJSON_GetObjectItemCaseSensitive(json, field); \
  bool field_var; \
  if (cJSON_IsTrue(_json_field_var)) { \
    field_var = true; \
  } else if (cJSON_IsFalse(_json_field_var)) { \
    field_var = false; \
  } else { \
    err.errcode = KeycloakE_JSON_Field; \
    err.data.str = field".boolean"; \
    goto gt; \
  }

#endif
