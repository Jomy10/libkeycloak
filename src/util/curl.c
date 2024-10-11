#include <keycloak/util/curl.h>
#include <keycloak/util/decorators.h>

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <stddef.h>
#include <str_builder/str_builder.h>

// #define _KEYCLOAK_LOG_REQS

size_t _keycloak_curl_writefunc(
  void* ptr,
  size_t size,
  size_t nmemb,
  str_builder_t* sb
) {
  str_builder_add_str(sb, ptr, size * nmemb);
  return size * nmemb;
}

void _keycloak_curl_init(
  CURL* curl,
  char* url,
  struct curl_slist* headers,
  str_builder_t* sb_output
) {
  curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  if (headers != NULL)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/8.2.1");
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

  // OUTPUT
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _keycloak_curl_writefunc);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, sb_output);

  #ifdef _KEYCLOAK_LOG_REQS
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  #endif

  // TODO: curl error
}

void _keycloak_curl_init_form(
  CURL* curl,
  char* url,
  struct curl_slist* headers,
  const char* postfields,
  str_builder_t* sb_output
) {
  headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

  _keycloak_curl_init(curl, url, headers, sb_output);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(postfields));
}
