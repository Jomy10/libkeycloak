#include <keycloak/jwt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <l8w8jwt/decode.h>

char* keycloak_jwt_validation_reason_string(KeycloakJWTValidationResult res) {
  switch (res) {
    case KeycloakV_VALID: return "Token valid";
    case KeycloakV_ISS_FAILURE: return "Issuer claim (ISS) mismatch";
    case KeycloakV_SUB_FAILURE: return "Subject claim (SUB) mismatch";
    case KeycloakV_AUD_FAILURE: return "Audience claim (AUD) mismatch";
    case KeycloakV_JTI_FAILURE: return "JWT ID claim (JTI) mismatch";
    case KeycloakV_EXP_FAILURE: return "Token is expired";
    case KeycloakV_NBF_FAILURE: return "Token is not yet valid";
    case KeycloakV_IAT_FAILURE: return "Token NULL, NULL, NULL, not issued yet";
    case KeycloakV_SIGNATURE_VERIFICATION_FAILURE: return "Token was potentially tempered with: its signature couldn't be verified";
    case KeycloakV_TYP_FAILURE: return "Typ claim validation failed";
  }
}

KeycloakError _keycloak_decode_and_validate_jwt(
  const KeycloakClient* __nonnull client,
  const KeycloakToken* __nonnull token,
  const char* __nullable validate_iss, const int validate_iss_length,
  const char* __nullable validate_sub, const int validate_sub_length,
  const char* __nullable validate_aud, const int validate_aud_length,
  const char* validate_jti, const int validate_jti_length,
  const char* validate_typ, const int validate_typ_length,
  const int validate_exp, const int exp_tolerance_seconds,
  const int validate_nbf, const int nbf_tolerance_seconds,
  const int validate_iat, const int iat_tolerance_seconds,
  KeycloakJWTValidationResult* __nonnull valid,
  struct l8w8jwt_claim** claims,
  size_t* claims_len
) {
  KeycloakError err;
  err.errcode = KeycloakE_OK;

  char* begpubkey = "-----BEGIN PUBLIC KEY-----\n";
  char* endpubkey = "\n-----END PUBLIC KEY-----";
  char pubkey[strlen(begpubkey) + strlen(client->realm_info.public_key) + strlen(endpubkey) + 1];
  sprintf(pubkey, "%s%s%s", begpubkey, client->realm_info.public_key, endpubkey);

  struct l8w8jwt_decoding_params params;
  l8w8jwt_decoding_params_init(&params);

  params.alg = L8W8JWT_ALG_RS256;
  params.jwt = token->token;
  params.jwt_length = strlen(token->token);
  params.verification_key = (unsigned char*) pubkey;
  params.verification_key_length = strlen(pubkey);

  params.validate_iss = (char*) validate_iss;
  params.validate_iss_length = validate_iss_length;
  params.validate_sub = (char*) validate_sub;
  params.validate_sub_length = validate_sub_length;
  params.validate_aud = (char*) validate_aud;
  params.validate_aud_length = validate_aud_length;
  params.validate_jti = (char*) validate_jti;
  params.validate_jti_length = validate_jti_length;
  params.validate_typ = (char*) validate_typ;
  params.validate_typ_length = validate_typ_length;
  params.validate_exp = validate_exp;
  params.exp_tolerance_seconds = exp_tolerance_seconds;
  params.validate_nbf = validate_nbf;
  params.nbf_tolerance_seconds = nbf_tolerance_seconds;
  params.validate_iat = validate_iat;
  params.iat_tolerance_seconds = iat_tolerance_seconds;

  enum l8w8jwt_validation_result validation_result;
  int decode_result = l8w8jwt_decode(&params, &validation_result, claims, claims_len);
  if (decode_result != L8W8JWT_SUCCESS) {
    if (decode_result == L8W8JWT_OUT_OF_MEM) {
      err.errcode = KeycloakE_OutOfMemory;
      return err;
    }
    err.errcode = KeycloakE_JWTDecode;
    err.data.code = decode_result;
    return err;
  }

  *valid = (KeycloakJWTValidationResult) validation_result;

  return err;
}

KeycloakError keycloak_validate_jwt(
  const KeycloakClient* client,
  const KeycloakToken* token,
  KeycloakJWTValidationResult* valid
) {
  return keycloak_validate_jwt_ex(
    client,
    token,
    NULL, 0, // iss
    NULL, 0, // sub
    NULL, 0, // aud
    NULL, 0, // jti
    NULL, 0, // typ
    1, 0, // exp
    0, 0, // nbf
    0, 0, // iat
    valid
  );
}

KeycloakError keycloak_validate_jwt_ex(
  const KeycloakClient* client,
  const KeycloakToken* token,
  const char* validate_iss, const int validate_iss_length,
  const char* validate_sub, const int validate_sub_length,
  const char* validate_aud, const int validate_aud_length,
  const char* validate_jti, const int validate_jti_length,
  const char* validate_typ, const int validate_typ_length,
  const bool validate_exp, const int exp_tolerance_seconds,
  const bool validate_nbf, const int nbf_tolerance_seconds,
  const bool validate_iat, const int iat_tolerance_seconds,
  KeycloakJWTValidationResult* valid
) {
  return _keycloak_decode_and_validate_jwt(
    client,
    token,
    validate_iss, validate_iss_length,
    validate_sub, validate_sub_length,
    validate_aud, validate_aud_length,
    validate_jti, validate_jti_length,
    validate_typ, validate_typ_length,
    validate_exp, exp_tolerance_seconds,
    validate_nbf, nbf_tolerance_seconds,
    validate_iat, iat_tolerance_seconds,
    valid,
    NULL, NULL
  );
}

KeycloakError keycloak_decode_and_validate_jwt(
  const KeycloakClient* client,
  const KeycloakToken* token,
  KeycloakJWTValidationResult* valid,
  KeycloakJWT* out_jwt
) {
  return keycloak_decode_and_validate_jwt_ex(
    client,
    token,
    NULL, 0, // iss
    NULL, 0, // sub
    NULL, 0, // aud
    NULL, 0, // jti
    NULL, 0, // typ
    1, 0, // exp
    0, 0, // nbf
    0, 0, // iat
    valid,
    out_jwt
  );
}

KeycloakError keycloak_decode_and_validate_jwt_ex(
  const KeycloakClient* client,
  const KeycloakToken* token,
  const char* validate_iss, const int validate_iss_length,
  const char* validate_sub, const int validate_sub_length,
  const char* validate_aud, const int validate_aud_length,
  const char* validate_jti, const int validate_jti_length,
  const char* validate_typ, const int validate_typ_length,
  const bool validate_exp, const int exp_tolerance_seconds,
  const bool validate_nbf, const int nbf_tolerance_seconds,
  const bool validate_iat, const int iat_tolerance_seconds,
  KeycloakJWTValidationResult* valid,
  KeycloakJWT* jwt
) {
  struct l8w8jwt_claim* claims;
  size_t claims_len;
  KeycloakError err = _keycloak_decode_and_validate_jwt(
    client,
    token,
    validate_iss, validate_iss_length,
    validate_sub, validate_sub_length,
    validate_aud, validate_aud_length,
    validate_jti, validate_jti_length,
    validate_typ, validate_typ_length,
    validate_exp, exp_tolerance_seconds,
    validate_nbf, nbf_tolerance_seconds,
    validate_iat, iat_tolerance_seconds,
    valid,
    &claims, &claims_len
  );

  jwt->data = (void*) claims;
  jwt->len = claims_len;

  return err;
}

void keycloak_destroy_jwt(KeycloakJWT* jwt) {
  l8w8jwt_free_claims(jwt->data, jwt->len);
}

KeycloakError keycloak_jwt_get_claim(
  const KeycloakJWT* jwt,
  const char* claim_key,
  KeycloakJWTClaim* claim_value
) {
  KeycloakError err;
  err.errcode = KeycloakE_OK;

  struct l8w8jwt_claim* claim = l8w8jwt_get_claim(jwt->data, jwt->len, claim_key, sizeof(claim_key));
  if (claim == NULL) {
    err.errcode = KeycloakE_JWTInvalidClaimKey;
    err.data.str = (char*) claim_key;
    return err;
  }
  claim_value->type = claim->type;
  claim_value->key = claim->key;

  switch ((KeycloakClaimType) claim->type) {
    case KeycloakCT_String:
      claim_value->value.stringvalue = claim->value;
      break;
    case KeycloakCT_Int:
      claim_value->value.intvalue = atoi(claim->value);
      break;
    case KeycloakCT_Double:
      claim_value->value.doublevalue = atof(claim->value);
      break;
    case KeycloakCT_Bool:
      claim_value->value.boolvalue = strcmp(claim->value, "true");
      break;
    case KeycloakCT_Null:
      claim_value->value.datavalue = NULL;
      break;
    // TODO:
    case KeycloakCT_Array:
      claim_value->value.datavalue = claim->value;
      break;
    case KeycloakCT_Object:
      claim_value->value.datavalue = claim->value;
      break;
    case KeycloakCT_Other:
      claim_value->value.datavalue = claim->value;
      break;
  }

  return err;
}

// TODO: decode without validation -> l8w8jwt_decode_Raw_no_validation
