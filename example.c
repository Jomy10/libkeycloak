#include <stdio.h>
#include <stdlib.h>

#define KEYCLOAK_LOG_DEBUG 1
#include "src/keycloak.h"

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
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [user] [password]\n", argv[0]);
    return 1;
  }

  printf("Reading client config at keycloak.json\n");
  char* jsonfile = "keycloak.json";
  char* jsonstr = read_to_string(jsonfile);
  if (!jsonstr) {
    fprintf(stderr, "Error readig %s\n", jsonfile);
    return 1;
  }

  KeycloakClient client;
  keycloak_client_init_from_json(&client, jsonstr);

  printf("-- Client info --\n");
  printf("Realm: %s\n", client.realm);
  printf("Client: %s\n", client.resource);
  printf("Auth url: %s\n", client.auth_server_url);

  printf("-- Authenticating User --\n");
  printf("User: %s\n", argv[1]);
  printf("Password: %s\n", argv[2]);

  char* token_response = NULL;
  long status_code;
  int ret = keycloak_get_token(&client, argv[1], argv[2], &token_response, &status_code);
  if (ret || status_code != 200) {
    fprintf(stderr, "Couldn't retrieve token for user (return code %i, http status code %li)\n", ret, status_code);
  }
  printf("%s\n", token_response);

  keycloak_client_deinit(&client);

  return 0;
}
