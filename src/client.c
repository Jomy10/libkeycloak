#include <keycloak/keycloak.h>
#include <keycloak/util/json.h>
#include <keycloak/util/curl.h>

#include <stdio.h>

#include <curl/curl.h>
#include <cJSON/cJSON.h>
#include <str_builder/str_builder.h>

void _keycloak_endpoint_baseurl(const KeycloakClient* client, str_builder_t* sb) {
  str_builder_add_str(sb, client->auth_server_url, 0);
  str_builder_add_str(sb, "/realms/", 0);
  str_builder_add_str(sb, client->realm, 0);
}

KeycloakError _keycloak_client_parse_json(
  KeycloakClient* client,
  const char* const jsonstr
) {
  KeycloakError e = { 0 };

  _JSON_PARSE(json, jsonstr, e);

  _JSON_GET_STRING_VALUE(json, realm, e, _kc_parse_json_err);
  _JSON_GET_STRING_VALUE_VAR(json, auth_server_url, "auth-server-url", e, _kc_parse_json_err);
  _JSON_GET_STRING_VALUE(json, resource, e, _kc_parse_json_err);
  _JSON_GET_OBJECT_VALUE(json, credentials, e, _kc_parse_json_err);
  _JSON_GET_STRING_VALUE(credentials, secret, e, _kc_parse_json_err);

  client->_json = json;
  client->realm = realm->valuestring;
  client->auth_server_url = auth_server_url->valuestring;
  client->resource = resource->valuestring;
  client->secret = secret->valuestring;

  return e;

_kc_parse_json_err:
  cJSON_Delete(json);
  return e;
}

KeycloakError _keycloak_client_realminfo(KeycloakClient* client) {
  KeycloakError err = { 0 };

  // Base URL
  str_builder_t* sb;
  sb = str_builder_create();

  _keycloak_endpoint_baseurl(client, sb);
  char* realm_info_url = str_builder_dump(sb, NULL);

  str_builder_clear(sb);

  // Request json
  CURLcode ret;
  CURL* curl;

  curl = curl_easy_init();

  _keycloak_curl_init(curl, realm_info_url, NULL, sb);

  ret = curl_easy_perform(curl);
  if (ret != CURLE_OK) {
    err.errcode = KeycloakE_CURL;
    err.data.str = (char*) curl_easy_strerror(ret);
    str_builder_destroy(sb);
    return err;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &ret);
  if (ret != 200) {
    if (ret == 0) {
      err.errcode = KeycloakE_CURL;
      err.data.str = NULL;
      str_builder_destroy(sb);
      return err;
    } else {
      err.errcode = KeycloakE_HTTP;
      err.data.code = ret;
      str_builder_destroy(sb);
      return err;
    }
  }

  char* response = str_builder_dump(sb, NULL);
  str_builder_destroy(sb);

  // Parse JSON
  _JSON_PARSE(realm_info_json, response, err);

  // TODO: realm_info fields
  // public_key, token_Service, etc.

  _JSON_GET_STRING_VALUE(realm_info_json, public_key, err, _kc_realminfo_json_err);
  _JSON_GET_STRING_VALUE_VAR(realm_info_json, token_service, "token-service", err, _kc_realminfo_json_err);
  _JSON_GET_STRING_VALUE_VAR(realm_info_json, account_service, "account-service", err, _kc_realminfo_json_err);

  client->realm_info._json = realm_info_json;
  client->realm_info.public_key = public_key->valuestring;
  client->realm_info.token_service = token_service->valuestring;
  client->realm_info.account_service = account_service->valuestring;

  return err;

_kc_realminfo_json_err:
  cJSON_Delete(realm_info_json);
  return err;
}

KeycloakError keycloak_create_client(
  KeycloakClient* client,
  const char* const jsonstr,
  const char options
) {
  KeycloakError err;
  err = _keycloak_client_parse_json(client, jsonstr);
  if (err.errcode != KeycloakE_OK) return err;

  err = _keycloak_client_realminfo(client);
  return err;
}

void keycloak_destroy_client(KeycloakClient* client) {
  cJSON_Delete(client->realm_info._json);
  cJSON_Delete(client->_json);
}
