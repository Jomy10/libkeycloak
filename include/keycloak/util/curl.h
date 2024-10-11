#ifndef _KEYCLOAK_CURL_H
#define _KEYCLOAK_CURL_H

#include <stdlib.h>
#include <str_builder/str_builder.h>
#include <curl/curl.h>

size_t _keycloak_curl_writefunc(
  void* ptr,
  size_t size,
  size_t nmemb,
  str_builder_t* sb
);

void _keycloak_curl_init(
  CURL* __nonnull curl,
  char* __nonnull url,
  struct curl_slist* __nullable headers,
  str_builder_t* __nonnull sb_output
);

void _keycloak_curl_init_form(
  CURL* __nonnull curl,
  char* __nonnull url,
  struct curl_slist* __nullable headers,
  const char* __nonnull postfields,
  str_builder_t* __nonnull sb_output
);

#endif
