#include <keycloak/keycloak.h>
#include <keycloak/util/postfield.h>
#include <keycloak/util/curl.h>
#include <keycloak/util/json.h>

#include <curl/curl.h>
#include <cJSON/cJSON.h>
#include <str_builder/str_builder.h>

#define _KEYCLOAK_HTTP_ERR_CHECK(curl_ret, err_response, response, gt) \
if (curl_ret != 200) { \
  if (curl_ret == 0) { \
    err.errcode = KeycloakE_CURL; \
    err.data.str = NULL; \
    goto gt; \
  } else { \
    err.errcode = KeycloakE_HTTP; \
    err.data.code = curl_ret; \
 \
    if (err_response != NULL) \
      *err_response = response; \
 \
    goto gt; \
  } \
}

char* _keycloak_format_scope(const char** scopes, const int scopes_len) {
  str_builder_t* sb = str_builder_create();
  char* scope;
  for (int i = 0; i < scopes_len; i++) {
    str_builder_add_str(sb, scopes[i], 0);
    if (i != scopes_len - 1)
      str_builder_add_str(sb, "%20", 0);
  }
  scope = str_builder_dump(sb, NULL);
  str_builder_destroy(sb);
  return scope;
}

// we need this because there's a hard to reproduce bug if we just inline this code
CURLcode _keycloak_http_response_code(CURL* curl) {
  CURLcode c;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &c);
  return c;
}

#include <assert.h>

void keycloak_destroy_tokens(KeycloakTokens* tokens) {
  cJSON_Delete(tokens->_json);
}

KeycloakError keycloak_get_token(
  const KeycloakClient* client,
  const char* user,
  const char* pass,
  const char** scopes,
  const int scopes_len,
  KeycloakTokens* tokens,
  char** err_response
) {
  KeycloakError err;
  err.errcode = KeycloakE_OK;

  CURLcode curl_ret;
  CURL* curl;
  struct curl_slist* headers;

  headers = NULL;
  curl = curl_easy_init();

  str_builder_t* sb;
  sb = str_builder_create();

  char* get_token_url;
  str_builder_add_str(sb, client->realm_info.token_service, 0);
  str_builder_add_str(sb, "/token", 0);
  get_token_url = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  char* postfields;
  _keycloak_add_postfield(sb, "client_id", client->resource);
  _keycloak_add_postfield(sb, "client_secret", client->secret);
  _keycloak_add_postfield(sb, "username", user);
  _keycloak_add_postfield(sb, "password", pass);
  _keycloak_add_postfield(sb, "grant_type", "password");
  if (scopes_len > 0) {
    char* scope = _keycloak_format_scope(scopes, scopes_len);
    _keycloak_add_postfield(sb, "scope", scope);
    free(scope);
  }
  postfields = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  _keycloak_curl_init_form(
    curl,
    get_token_url,
    headers,
    postfields,
    sb
  );

  // Execute request
  curl_ret = curl_easy_perform(curl);
  if (curl_ret != CURLE_OK) {
    err.errcode = KeycloakE_CURL;
    err.data.str = (char*) curl_easy_strerror(curl_ret);
    goto _kc_token_service_ret;
  }

  char* response = str_builder_dump(sb, NULL);

  // int c = _keycloak_check_http_response_code(curl, &err);
  curl_ret = _keycloak_http_response_code(curl);
  _KEYCLOAK_HTTP_ERR_CHECK(curl_ret, err_response, response, _kc_token_service_ret);

  // Parse result
  _JSON_PARSE_GOTO(json, response, err, _kc_token_service_ret);

  _JSON_GET_STRING_VALUE(json, access_token, err, _kc_token_service_json_err);
  _JSON_GET_NUMBER_VALUE(json, expires_in, err, _kc_token_service_json_err);
  _JSON_GET_NUMBER_VALUE(json, refresh_expires_in, err, _kc_token_service_json_err);
  _JSON_GET_STRING_VALUE(json, refresh_token, err, _kc_token_service_json_err);
  _JSON_GET_STRING_VALUE(json, token_type, err, _kc_token_service_json_err);
  _JSON_GET_NUMBER_VALUE_VAR(json, not_before_policy, "not-before-policy", err, _kc_token_service_json_err);
  _JSON_GET_STRING_VALUE(json, session_state, err, _kc_token_service_json_err);
  _JSON_GET_STRING_VALUE(json, scope, err, _kc_token_service_json_err);

  tokens->access_token.token = access_token->valuestring;
  tokens->access_token.expiration = expires_in->valueint;
  tokens->refresh_token.token = refresh_token->valuestring;
  tokens->refresh_token.expiration = refresh_expires_in->valueint;
  tokens->token_type = token_type->valuestring;
  tokens->not_before_policy = not_before_policy->valueint;
  tokens->session_state = session_state->valuestring;
  tokens->scope = scope->valuestring;
  tokens->_json = json;

  goto _kc_token_service_ret;

_kc_token_service_json_err:
  cJSON_free(json);

_kc_token_service_ret:
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  str_builder_destroy(sb);
  free(get_token_url);
  free(postfields);
  if (err_response == NULL)
    free(response);

  return err;
}

KeycloakError keycloak_refresh_token(
  const KeycloakClient* client,
  const KeycloakToken _refresh_token,
  const char** scopes,
  const int scopes_len,
  KeycloakTokens* tokens,
  char** err_response
) {
  char* refresh_token = _refresh_token.token;

  KeycloakError err;
  err.errcode = KeycloakE_OK;

  CURLcode curl_ret;
  CURL* curl;
  struct curl_slist* headers;

  headers = NULL;
  curl = curl_easy_init();

  str_builder_t* sb;
  sb = str_builder_create();

  char* token_endpoint;
  str_builder_add_str(sb, client->realm_info.token_service, 0);
  str_builder_add_str(sb, "/token", 0);
  token_endpoint = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  char* postfields;
  _keycloak_add_postfield(sb, "client_id", client->resource);
  _keycloak_add_postfield(sb, "client_secret", client->secret);
  _keycloak_add_postfield(sb, "grant_type", "refresh_token");
  _keycloak_add_postfield(sb, "refresh_token", refresh_token);
  if (scopes_len > 0) {
    char* scope = _keycloak_format_scope(scopes, scopes_len);
    _keycloak_add_postfield(sb, "scope", scope);
    free(scope);
  }
  postfields = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  _keycloak_curl_init_form(
    curl,
    token_endpoint,
    headers,
    postfields,
    sb
  );

  // Execute request
  curl_ret = curl_easy_perform(curl);
  if (curl_ret != CURLE_OK) {
    err.errcode = KeycloakE_CURL;
    err.data.str = (char*) curl_easy_strerror(curl_ret);
    goto _kc_token_refresh_ret;
  }

  char* response = str_builder_dump(sb, NULL);

  curl_ret = _keycloak_http_response_code(curl);
  if (curl_ret != 200) {
    if (curl_ret == 0) {
      err.errcode = KeycloakE_CURL;
      err.data.str = NULL;

      goto _kc_token_refresh_ret;
    } else {
      err.errcode = KeycloakE_HTTP;
      err.data.code = curl_ret;

      if (err_response != NULL)
        *err_response = response;

      goto _kc_token_refresh_ret;
    }
  }


  // Parse result
  _JSON_PARSE_GOTO(json, response, err, _kc_token_refresh_json_err);

  _JSON_GET_STRING_VALUE(json, access_token, err, _kc_token_refresh_json_err);
  _JSON_GET_NUMBER_VALUE(json, expires_in, err, _kc_token_refresh_json_err);
  _JSON_GET_NUMBER_VALUE(json, refresh_expires_in, err, _kc_token_refresh_json_err);
  _JSON_GET_STRING_VALUE_VAR(json, json_refresh_token, "refresh_token", err, _kc_token_refresh_json_err);
  _JSON_GET_STRING_VALUE(json, token_type, err, _kc_token_refresh_json_err);
  _JSON_GET_NUMBER_VALUE_VAR(json, not_before_policy, "not-before-policy", err, _kc_token_refresh_json_err);
  _JSON_GET_STRING_VALUE(json, session_state, err, _kc_token_refresh_json_err);
  _JSON_GET_STRING_VALUE(json, scope, err, _kc_token_refresh_json_err);

  tokens->access_token.token = access_token->valuestring;
  tokens->access_token.expiration = expires_in->valueint;
  tokens->refresh_token.token = json_refresh_token->valuestring;
  tokens->refresh_token.expiration = refresh_expires_in->valueint;
  tokens->token_type = token_type->valuestring;
  tokens->not_before_policy = not_before_policy->valueint;
  tokens->session_state = session_state->valuestring;
  tokens->scope = scope->valuestring;
  tokens->_json = json;

  goto _kc_token_refresh_ret;

_kc_token_refresh_json_err:
  cJSON_free(json);

_kc_token_refresh_ret:
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  str_builder_destroy(sb);
  free(token_endpoint);
  free(postfields);
  return err;
}

void keycloak_destroy_userinfo(KeycloakUserinfo *info) {
  cJSON_Delete(info->_json);
}

KeycloakError keycloak_get_userinfo(
  const KeycloakClient* client,
  const KeycloakTokens* tokens,
  KeycloakUserinfo* userinfo,
  char** err_response
) {
  KeycloakError err;
  err.errcode = KeycloakE_OK;

  CURLcode curl_ret;
  CURL* curl;
  struct curl_slist* headers;

  headers = NULL;
  curl = curl_easy_init();

  str_builder_t* sb;
  sb = str_builder_create();

  char* auth_header;
  str_builder_add_str(sb, "Authorization: ", 0);
  str_builder_add_str(sb, tokens->token_type, 0);
  str_builder_add_str(sb, " ", 0);
  str_builder_add_str(sb, tokens->access_token.token, 0);
  auth_header = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  headers = curl_slist_append(headers, auth_header);

  char* userinfo_endpoint;
  str_builder_add_str(sb, client->realm_info.token_service, 0);
  str_builder_add_str(sb, "/userinfo", 0);
  userinfo_endpoint = str_builder_dump(sb, NULL);
  str_builder_clear(sb);

  _keycloak_curl_init(
    curl,
    userinfo_endpoint,
    headers,
    sb
  );
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

  curl_ret = curl_easy_perform(curl);
  if (curl_ret != CURLE_OK) {
    err.errcode = KeycloakE_CURL;
    err.data.str = (char*) curl_easy_strerror(curl_ret);
    goto _kc_userinfo_ret;
  }

  char* response = str_builder_dump(sb, NULL);

  curl_ret = _keycloak_http_response_code(curl);
  _KEYCLOAK_HTTP_ERR_CHECK(curl_ret, err_response, response, _kc_userinfo_ret);

  // Parse result
  _JSON_PARSE_GOTO(json, response, err, _kc_userinfo_ret);

  _JSON_GET_STRING_VALUE(json, sub, err, _kc_userinfo_json_err);
  _JSON_GET_BOOL_VALUE(json, email_verified, err, _kc_userinfo_json_err);
  _JSON_GET_STRING_VALUE(json, name, err, _kc_userinfo_json_err);
  _JSON_GET_STRING_VALUE(json, preferred_username, err, _kc_userinfo_json_err);
  _JSON_GET_STRING_VALUE(json, given_name, err, _kc_userinfo_json_err);
  _JSON_GET_STRING_VALUE(json, family_name, err, _kc_userinfo_json_err);
  _JSON_GET_STRING_VALUE(json, email, err, _kc_userinfo_json_err);

  userinfo->_json = json;
  userinfo->email_verified = email_verified;
  userinfo->name = name->valuestring;
  userinfo->preferred_username = preferred_username->valuestring;
  userinfo->given_name = given_name->valuestring;
  userinfo->family_name = family_name->valuestring;
  userinfo->email = email->valuestring;

  goto _kc_userinfo_ret;
_kc_userinfo_json_err:
  cJSON_Delete(json);

_kc_userinfo_ret:
  str_builder_destroy(sb);
  free(auth_header);
  free(userinfo_endpoint);
  if (err_response == NULL)
    free(response);

  return err;
}
