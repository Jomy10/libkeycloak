#include "keycloak.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON/cJSON.h>
#include <curl/curl.h>
#include <str_builder/str_builder.h>

#if KEYCLOAK_LOG_LEVEL == 5
#define _LOG_REQS
#endif

/// Returns 0 if ok
int keycloak_client_init_from_json(KeycloakClient* client, const char* const jsonstr) {
  cJSON* json = cJSON_Parse(jsonstr);
  if (json == NULL) {
    const char* errptr = cJSON_GetErrorPtr();
    if (errptr != NULL) {
      fprintf(stderr, "Error before: %s\n", errptr);
    }
    goto errend;
  }

  const cJSON* realm = cJSON_GetObjectItemCaseSensitive(json, "realm");
  if (!cJSON_IsString(realm) || (realm->valuestring == NULL)) {
    fprintf(stderr, "'realm' is not a string or doesn't exist");
    goto errend;
  }

  const cJSON* auth_server_url = cJSON_GetObjectItemCaseSensitive(json, "auth-server-url");
  if (!cJSON_IsString(auth_server_url) || (auth_server_url->valuestring == NULL)) {
    fprintf(stderr, "'auth-server-url' is not a string or doesn't exist");
    goto errend;
  }

  const cJSON* resource = cJSON_GetObjectItemCaseSensitive(json, "resource");
  if (!cJSON_IsString(resource) || (resource->valuestring == NULL)) {
    fprintf(stderr, "'resource' is not a string or doesn't exist");
    goto errend;
  }

  const cJSON* credentials = cJSON_GetObjectItemCaseSensitive(json, "credentials");
  if (!cJSON_IsObject(credentials) || (credentials->child == NULL)) {
    fprintf(stderr, "'credentials' is not an object, has no children or doesn't exist");
    goto errend;
  }

  const cJSON* secret = cJSON_GetObjectItemCaseSensitive(credentials, "secret");
  if (!cJSON_IsString(secret) || (secret->valuestring == NULL)) {
    fprintf(stderr, "'credentials.secret' is not a string or doesn't exist");
    goto errend;
  }

  client->json_obj = json;
  client->realm = realm->valuestring;
  client->auth_server_url = auth_server_url->valuestring;
  client->resource = resource->valuestring;
  client->secret = secret->valuestring;

  return 0;

  errend:
    cJSON_Delete(json);
    return 1;
}

void keycloak_client_deinit(KeycloakClient* client) {
  cJSON_Delete(client->json_obj);
  client->json_obj = NULL;
  client->auth_server_url = NULL;
  client->realm = NULL;
  client->secret = NULL;
}

struct _keycloak_string {
  char* ptr;
  size_t len;
};

void _init_keycloak_string(struct _keycloak_string* s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t _keycloak_curl_writefunc(void* ptr, size_t size, size_t nmemb, struct _keycloak_string* s) {
  size_t new_len = s->len + size * nmemb;
  if (new_len > s->len)
    s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

void _keycloak_curl_init(
  CURL* curl,
  struct curl_slist* headers,
  char* url,
  char* postfields
) {
  headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

  curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(postfields));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.2.1");
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
}

CURLcode _keycloak_curl_output(CURL* curl, struct _keycloak_string* s) {
  CURLcode ret;

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _keycloak_curl_writefunc);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);

  ret = curl_easy_perform(curl);

  return ret;
}

/// Returns a [CURL error code](https://curl.se/libcurl/c/libcurl-errors.html).
/// response is filled with the response of the API call. This should be freed manually.
/// http_status_code s filled with the status code of the request
int keycloak_get_token(
  const KeycloakClient* client,
  const char* user,
  const char* password,
  char** response,
  long* http_status_code
) {
  CURLcode ret;
  CURL* curl;
  struct curl_slist* headers;

  headers = NULL;
  curl = curl_easy_init();

  str_builder_t* sb;
  char* get_token_url;

  sb = str_builder_create();
  str_builder_add_str(sb, client->auth_server_url, 0);
  str_builder_add_str(sb, "/realms/", 0);
  str_builder_add_str(sb, client->realm, 0);
  str_builder_add_str(sb, "/protocol/openid-connect/token", 0);
  get_token_url = str_builder_dump(sb, NULL);
  str_builder_destroy(sb);

  #ifdef _LOG_REQS
  printf("url: %s\n", get_token_url);
  #endif

  char* postfields;
  sb = str_builder_create();
  str_builder_add_str(sb, "client_id=", 0);
  str_builder_add_str(sb, client->resource, 0);
  str_builder_add_str(sb, "&client_secret=", 0);
  str_builder_add_str(sb, client->secret, 0);
  str_builder_add_str(sb, "&username=", 0);
  str_builder_add_str(sb, user, 0);
  str_builder_add_str(sb, "&password=", 0);
  str_builder_add_str(sb, password, 0);
  str_builder_add_str(sb, "&grant_type=password", 0);
  postfields = str_builder_dump(sb, NULL);
  str_builder_destroy(sb);

  #ifdef _LOG_REQS
  printf("post fields: %s\n", postfields);
  #endif

  _keycloak_curl_init(
    curl,
    headers,
    get_token_url,
    postfields
  );

  // Execute request
  struct _keycloak_string s;
  _init_keycloak_string(&s);
  ret = _keycloak_curl_output(curl, &s);

  // Response
  *response = s.ptr;
  *http_status_code = 0;
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, http_status_code);

  // Cleanup
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  free(get_token_url);
  free(postfields);

  return (int) ret;
}
