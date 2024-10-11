#ifndef _KEYCLOAK_ERROR_H
#define _KEYCLOAK_ERROR_H

typedef enum {
  KeycloakE_OK = 0,
  KeycloakE_JSON_Parse,
  KeycloakE_JSON_Field,
  KeycloakE_No_JSON_Field,
  /// Error from curl itself
  KeycloakE_CURL,
  /// HTTP Status code
  KeycloakE_HTTP,
  /// An invalid token was found
  // KeycloakE_Token,

  /// Error decoding JWT
  KeycloakE_JWTDecode,

  /// Key doesn't correspond to a claim in the JWT
  KeycloakE_JWTInvalidClaimKey,

  KeycloakE_OutOfMemory,

  // KeycloakE_JWT,
  // KeycloakE_PublicKey,
  /// Error while verifying data using openssl
  // KeycloakE_OpenSSL, // <- data is errorcode using ERR_error_string
  // KeycloakE_NoRSA,
} KeycloakErrorCode;

typedef struct {
  KeycloakErrorCode errcode;
  union {
    char* str;
    unsigned long code;
  } data;
} KeycloakError;

void keycloak_errmsg(KeycloakError err, char* buf);

#endif
