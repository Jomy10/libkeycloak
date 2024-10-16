#ifndef _KEYCLOAK_TOKEN_SERVICE_H
#define _KEYCLOAK_TOKEN_SERVICE_H

#include "error.h"
#include "client.h"
#include "util/decorators.h"

#include <cJSON/cJSON.h>
#include <stdbool.h>

typedef struct {
  char* token;
  int expiration;
} KeycloakToken;

typedef struct {
  cJSON* _json;
  KeycloakToken access_token;
  KeycloakToken refresh_token;
  char* token_type;
  int not_before_policy;
  char* session_state;
  char* scope;
} KeycloakTokens;

void keycloak_destroy_tokens(KeycloakTokens* tokens);

KeycloakError keycloak_get_token(
  const KeycloakClient* __nonnull client,
  const char* __nonnull user,
  const char* __nonnull pass,
  const char** __nullable scopes,
  const int scopes_len,
  KeycloakTokens* __nonnull tokens,
  // optionally read the json response from the request. Must be freed
  char** __nullable err_response
);

KeycloakError keycloak_refresh_token(
  const KeycloakClient* __nonnull client,
  const KeycloakToken refresh_token,
  const char** __nullable scopes,
  const int scopes_len,
  KeycloakTokens* __nonnull tokens,
  char** __nullable err_response
);

typedef struct {
  cJSON* _json;
  char* sub;
  bool email_verified;
  char* name;
  char* preferred_username;
  char* given_name;
  char* family_name;
  char* email;
} KeycloakUserinfo;

void keycloak_destroy_userinfo(KeycloakUserinfo* info);

KeycloakError keycloak_get_userinfo(
  const KeycloakClient* __nonnull client,
  const KeycloakTokens* __nonnull tokens,
  KeycloakUserinfo* __nonnull userinfo,
  char** __nullable err_response
);

#endif
