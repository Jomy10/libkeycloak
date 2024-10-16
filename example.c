#include "keycloak/jwt.h"
#include <stdio.h>
#include <stdlib.h>

#define KEYCLOAK_LOG_DEBUG 1
#include <keycloak/keycloak.h>

#define CHECK_ERR(err) CHECK_ERR2(err, ({}))
#define CHECK_ERR2(err, custom_action) \
  if (err.errcode != KeycloakE_OK) { \
     char buf[1024]; \
     keycloak_errmsg(e, buf); \
     printf("Keycloak error (%i): %s\n", e.errcode, buf); \
     custom_action; \
     return 1; \
  }

char* read_to_string(char* file) {
  FILE* f = fopen(file, "r");
  char* buffer = NULL;
  long length;

  if (!f) {
    return NULL;
  }

  fseek(f, 0, SEEK_END);
  length = ftell(f);
  fseek(f, 0, SEEK_SET);
  buffer = malloc(length);
  if (!buffer) {
    return NULL;
  }
  fread(buffer, 1, length, f);
  fclose(f);

  return buffer;
}

int main(int argc, char** argv) {
  KeycloakError e;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s [user] [password]\n", argv[0]);
    return 1;
  }

  char* user = argv[1];
  char* pass = argv[2];

  printf("Reading client config at keycloak.json\n");
  char* jsonfile = "keycloak.json";
  char* jsonstr = read_to_string(jsonfile);
  if (!jsonstr) {
    fprintf(stderr, "Error readig %s\n", jsonfile);
    return 1;
  }

  printf("Retrieving client...\n");
  KeycloakClient client;
  e = keycloak_create_client(&client, jsonstr, 0);
  CHECK_ERR(e);

  printf("Retrieving token...\n");
  KeycloakTokens tokens;
  char* err_resp;
  char* scopes[1];
  scopes[0] = "openid";
  e = keycloak_get_token(&client, user, pass, (const char**) scopes, 1, &tokens, &err_resp);
  CHECK_ERR2(e, ({
    if (e.errcode == KeycloakE_HTTP) {
      printf("HTTP error: %s\n", err_resp);
      free(err_resp);
    }
  }));

  printf("token: %s\n", tokens.access_token.token);

  printf("Refreshing token...\n");
  KeycloakTokens refreshed_tokens;
  e = keycloak_refresh_token(&client, tokens.refresh_token, (const char**) scopes, 1, &refreshed_tokens, &err_resp);
  CHECK_ERR2(e, ({
    if (e.errcode == KeycloakE_HTTP) {
      printf("HTTP error: %s\n", err_resp);
      free(err_resp);
      return 1;
    }
  }));

  keycloak_destroy_tokens(&tokens);
  tokens = refreshed_tokens;

  printf("Refreshed token: %s\n", refreshed_tokens.access_token.token);

  printf("Getting userinfo...\n");
  KeycloakUserinfo userinfo;
  e = keycloak_get_userinfo(&client, &tokens, &userinfo, &err_resp);
  CHECK_ERR2(e, ({
    if (e.errcode == KeycloakE_HTTP) {
      printf("HTTP error: %s\n", err_resp);
      free(err_resp);
      return 1;
    }
  }));

  printf("Username: %s\n", userinfo.preferred_username);

  printf("Validating token...\n");

  KeycloakJWTValidationResult res;
  e = keycloak_validate_jwt(&client, &tokens.access_token, &res);
  CHECK_ERR(e);
  if (res == KeycloakV_VALID) {
    printf("Token valid\n");
  } else {
    printf("Token invalid (reason %s)\n", keycloak_jwt_validation_reason_string(res));
  }

  printf("Decoding and reading jwt...\n");
  KeycloakJWT jwt;
  e = keycloak_decode_and_validate_jwt_ex(
    &client,
    &tokens.access_token,
    NULL, 0,
    NULL, 0,
    NULL, 0,
    NULL, 0,
    NULL, 0,
    true, 0,
    false, 0,
    false, 0,
    &res,
    &jwt
  );
  CHECK_ERR(e);
  if (res != KeycloakV_VALID) {
    printf("Token invalid (reason %s)\n", keycloak_jwt_validation_reason_string(res));
  }

  KeycloakJWTClaim claim;
  keycloak_jwt_get_claim(&jwt, "iss", &claim);
  printf("iss = ");
  switch (claim.type) {
    case KeycloakCT_String:
      printf("%s\n", claim.value.stringvalue);
      break;
    case KeycloakCT_Int:
      printf("%i\n", claim.value.intvalue);
      break;
    case KeycloakCT_Double:
      printf("%f\n", claim.value.doublevalue);
      break;
    case KeycloakCT_Bool:
      printf("%s\n", claim.value.boolvalue == true ? "true" : "false");
      break;
    case KeycloakCT_Null:
      printf("null\n");
      break;
    case KeycloakCT_Array:
    case KeycloakCT_Object:
    case KeycloakCT_Other:
      printf("%p\n", claim.value.datavalue);
      break;
  }

  // we can destroy the copied tokens instead of the original `refreshed_tokens`
  // After this call we cannot use either of them
  keycloak_destroy_tokens(&tokens);
  keycloak_destroy_client(&client);

  return 0;
}
