#ifndef _KEYCLOAK_C_H_
#define _KEYCLOAK_C_H_

#include <cJSON/cJSON.h>

#define KEYCLOAK_LOG_LEVEL 0

typedef struct {
  cJSON* json_obj;
  char* realm;
  char* resource;
  char* auth_server_url;
  char* secret;
} KeycloakClient;

/// Returns 0 if ok
int keycloak_client_init_from_json(KeycloakClient* client, const char* const jsonstr);
void keycloak_client_deinit(KeycloakClient* client);

/// Returns a [CURL error code](https://curl.se/libcurl/c/libcurl-errors.html)
/// response is filled with the response of the API call. This should be freed manually
/// http_status_code s filled with the status code of the request
int keycloak_get_token(
  const KeycloakClient* client,
  const char* user,
  const char* password,
  char** response,
  long* http_status_code
);

#endif
