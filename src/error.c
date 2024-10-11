#include <keycloak/error.h>

#include <stdio.h>
#include <string.h>

#include <l8w8jwt/retcodes.h>

void keycloak_errmsg(KeycloakError err, char *buf) {
  switch (err.errcode) {
    case KeycloakE_OK:
      *buf = 0;
      break;
    case KeycloakE_JSON_Parse:
      sprintf(buf, "Error before: %s", err.data.str);
      break;
    case KeycloakE_JSON_Field: {
      int buflen = strlen(err.data.str);
      int part1len;
      char* part2;
      for (int i = 0; i < buflen; i++) {
        if (err.data.str[i] == '.') {
          part1len = i;
          part2 = err.data.str + i + 1;
          break;
        }
      }
      sprintf(buf, "'%.*s' is not a %s or not a field", part1len, err.data.str, part2);
    }; break;
    case KeycloakE_CURL:
      memcpy(buf, err.data.str, strlen(err.data.str));
      break;
    case KeycloakE_HTTP:
      sprintf(buf, "HTTP status code: %li", (long) err.data.code);
      break;
    case KeycloakE_No_JSON_Field:
      sprintf(buf, "No field named %s", err.data.str);
      break;
    case KeycloakE_JWTDecode:
      switch (err.data.code) {
        case L8W8JWT_NULL_ARG:
          sprintf(buf, "Argument was NULL, but wasn't expectinig NULL");
          break;
        case L8W8JWT_INVALID_ARG:
          sprintf(buf, "Invalid parameter");
          break;
        case L8W8JWT_OVERFLOW:
          sprintf(buf, "Overflow occurred");
          break;
        case L8W8JWT_SIGNATURE_CREATION_FAILURE:
          sprintf(buf, "Signing JWT failed");
          break;
        case L8W8JWT_SHA2_FAILURE:
          sprintf(buf, "SHA-2 function failed");
          break;
        case L8W8JWT_KEY_PARSE_FAILURE:
          sprintf(buf, "PEM-formatted key string couldn't be parsed (invalid public key)");
          break;
        case L8W8JWT_BASE64_FAILURE:
          sprintf(buf, "Decoding Base64 failed");
          break;
        case L8W8JWT_WRONG_KEY_TYPE:
          sprintf(buf, "Wrong private or public key");
          break;
        case L8W8JWT_MBEDTLS_CTR_DRBG_SEED_FAILURE:
          sprintf(buf, "mbedtls_ctr_drbg_seed() failed");
          break;
        case L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT:
          sprintf(buf, "Decode failed: Invalid token format");
          break;
        case L8W8JWT_DECODE_FAILED_MISSING_SIGNATURE:
          sprintf(buf, "Decode failed: Token is missing a signature");
          break;
        case L8W8JWT_UNSUPPORTED_ALG:
          sprintf(buf, "Unsuported algorithm for JWT signing");
          break;
      }
    case KeycloakE_OutOfMemory:
      sprintf(buf, "Out of memory!");
      break;
    case KeycloakE_JWTInvalidClaimKey:
      sprintf(buf, "No claim exists in the JWT with the key %s\n", err.data.str);
      break;
  }
}
