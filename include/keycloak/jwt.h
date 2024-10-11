#ifndef _KEYCLOAK_JWT_H
#define _KEYCLOAK_JWT_H

#include "client.h"
#include "token_service.h"

typedef enum {
  /**
     * The JWT is valid (according to the passed validation parameters).
     */
    KeycloakV_VALID = (unsigned)0,

    /**
     * The issuer claim is invalid.
     */
    KeycloakV_ISS_FAILURE = (unsigned)1 << (unsigned)0,

    /**
     * The subject claim is invalid.
     */
    KeycloakV_SUB_FAILURE = (unsigned)1 << (unsigned)1,

    /**
     * The audience claim is invalid.
     */
    KeycloakV_AUD_FAILURE = (unsigned)1 << (unsigned)2,

    /**
     * The JWT ID claim is invalid.
     */
    KeycloakV_JTI_FAILURE = (unsigned)1 << (unsigned)3,

    /**
     * The token is expired.
     */
    KeycloakV_EXP_FAILURE = (unsigned)1 << (unsigned)4,

    /**
     * The token is not yet valid.
     */
    KeycloakV_NBF_FAILURE = (unsigned)1 << (unsigned)5,

    /**
     * The token was not issued yet, are you from the future?
     */
    KeycloakV_IAT_FAILURE = (unsigned)1 << (unsigned)6,

    /**
     * The token was potentially tampered with: its signature couldn't be verified.
     */
    KeycloakV_SIGNATURE_VERIFICATION_FAILURE = (unsigned)1 << (unsigned)7,

    /**
     * The token's "typ" claim validation failed.
     */
    KeycloakV_TYP_FAILURE = (unsigned)1 << (unsigned)8
} KeycloakJWTValidationResult;

typedef struct {
  void* data;
  size_t len;
} KeycloakJWT;

typedef enum {
  KeycloakCT_String = 0,
  KeycloakCT_Int = 1,
  KeycloakCT_Double = 2,
  KeycloakCT_Bool = 3,
  KeycloakCT_Null = 4,
  KeycloakCT_Array = 5,
  KeycloakCT_Object = 6,
  KeycloakCT_Other = 7,
} KeycloakClaimType;

typedef struct {
  char* key;
  union {
    char* stringvalue;
    int intvalue;
    double doublevalue;
    bool boolvalue;
    void* datavalue;
  } value;
  int type;
} KeycloakJWTClaim;

/// Get the reason for a JWT validation error
char* keycloak_jwt_validation_reason_string(KeycloakJWTValidationResult res);

KeycloakError keycloak_validate_jwt(
  const KeycloakClient* __nonnull client,
  const KeycloakToken* __nonnull token,
  KeycloakJWTValidationResult* __nonnull valid
);

KeycloakError keycloak_validate_jwt_ex(
  const KeycloakClient* __nonnull client,
  const KeycloakToken* __nonnull token,
  const char* __nullable validate_iss,
  const int validate_iss_length,
  const char* __nullable validate_sub,
  const int validate_sub_length,
  const char* __nullable validate_aud,
  const int validate_aud_length,
  const char* validate_jti,
  const int validate_jti_length,
  const char* validate_typ,
  const int validate_typ_length,
  const int validate_exp,
  const int exp_tolerance_seconds,
  const int validate_nbf,
  const int nbf_tolerance_seconds,
  const int validate_iat,
  const int iat_tolerance_seconds,
  KeycloakJWTValidationResult* __nonnull valid
);

KeycloakError keycloak_decode_and_validate_jwt(
  const KeycloakClient* __nonnull client,
  const KeycloakToken* __nonnull token,
  KeycloakJWTValidationResult* __nonnull valid,
  KeycloakJWT* __nullable out_jwt
);

KeycloakError keycloak_decode_and_validate_jwt_ex(
  const KeycloakClient* __nonnull client,
  const KeycloakToken* __nonnull token,
  const char* __nullable validate_iss,
  const int validate_iss_length,
  const char* __nullable validate_sub,
  const int validate_sub_length,
  const char* __nullable validate_aud,
  const int validate_aud_length,
  const char* validate_jti,
  const int validate_jti_length,
  const char* validate_typ,
  const int validate_typ_length,
  const int validate_exp,
  const int exp_tolerance_seconds,
  const int validate_nbf,
  const int nbf_tolerance_seconds,
  const int validate_iat,
  const int iat_tolerance_seconds,
  KeycloakJWTValidationResult* __nonnull valid,
  KeycloakJWT* __nullable out_jwt
);

/// Get a claim by its key
/// Header claims are "alg", "typ", "kid"
/// Payload claims are e.g. "iss", "aud", ...
KeycloakError keycloak_jwt_get_claim(
  const KeycloakJWT* __nonnull jwt,
  /// Should outlive a call to `keycloak_errmsg` called on the return value of this function
  const char* __nonnull claim_key,
  /// Claim returned if error is OK
  KeycloakJWTClaim* __nonnull claim_value
);

#endif
