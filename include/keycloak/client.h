#ifndef _KEYCLOAK_CLIENT_H
#define _KEYCLOAK_CLIENT_H

#include "error.h"
#include <cJSON/cJSON.h>

typedef struct {
  cJSON* _json;
  char* public_key;
  char* token_service;
  char* account_service;
} KeycloakRealm;

typedef struct {
  cJSON* _json;
  char* realm;
  char* resource;
  char* auth_server_url;
  char* secret;
  KeycloakRealm realm_info;
} KeycloakClient;

KeycloakError keycloak_create_client(
  KeycloakClient* client,
  const char* const jsonstr,
  const char options
);

void keycloak_destroy_client(KeycloakClient* client);

#endif
