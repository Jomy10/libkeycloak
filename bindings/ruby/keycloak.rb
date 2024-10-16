require 'ffi'
require 'ffi/libc'

module Keycloak_FFI
  extend FFI::Library

  ffi_lib 'keycloak'

  # Error
  enum :KeycloakErrorCode, [
    :OK, 0,
    :JSON_Parse,
    :JSON_Field,
    :No_JSON_Field,
    :CURL,
    :HTTP,
    :JWTDecode,
    :JWTInvalidClaimKey,
    :OutOfMemory,
  ]

  class KeycloakErrorData < FFI::Union
    layout :str, :string,
           :code, :ulong
  end

  class KeycloakError < FFI::Struct
    layout :errcode, :KeycloakErrorCode,
           :data, KeycloakErrorData.val
  end

  attach_function :keycloak_errmsg, [KeycloakError.val, :pointer], :void

  # Client
  class KeycloakRealm < FFI::Struct
    layout :_json, :pointer,
           :public_key, :string,
           :token_service, :string,
           :account_service, :string

    def public_key
      self[:public_key]
    end

    def token_service
      self[:token_service]
    end

    def account_service
      self[:account_service]
    end
  end

  class KeycloakClient < FFI::ManagedStruct
    layout :_json, :pointer,
           :realm, :string,
           :resource, :string,
           :auth_server_url, :string,
           :secret, :string,
           :realm_info, KeycloakRealm.val

    def self.release ptr
      unless ptr.nil?
        Keycloak_FFI.keycloak_destroy_client(ptr)
        FFI::LibC.free(ptr)
      end
    end
  end

  attach_function :keycloak_create_client, [
    KeycloakClient.ptr,
    :string, # jsonstr
    :char # options
  ], KeycloakError.val

  attach_function :keycloak_destroy_client, [:pointer], :void

  # Token service

  class KeycloakToken < FFI::Struct
    layout :token, :string,
           :expiration, :int

    def token
      self[:token]
    end

    def expiration
      self[:token]
    end
  end

  class KeycloakTokens < FFI::ManagedStruct
    layout :_json, :pointer,
           :access_token, KeycloakToken.val,
           :refresh_token, KeycloakToken.val,
           :token_type, :string,
           :not_before_policy, :int,
           :session_state, :string,
           :scope, :string

    def self.release ptr
      unless ptr.nil?
        Keycloak_FFI.keycloak_destroy_tokens(ptr)
        FFI::LibC.free(ptr)
      end
    end

    def access_token
      return self[:access_token]
    end

    def refresh_token
      return self[:refresh_token]
    end

    def token_type
      return self[:token_type]
    end

    def not_before_policy
      return self[:not_before_policy]
    end

    def session_state
      return self[:session_state]
    end

    def scope
      return self[:scope]
    end

    def scopes
      return self.scope.split " "
    end
  end

  attach_function :keycloak_destroy_tokens, [:pointer], :void

  attach_function :keycloak_get_token, [
    KeycloakClient.ptr,
    :string, # user
    :string, # pass
    :pointer, # scopes
    :int, # scopes_len
    KeycloakTokens.ptr, # out tokens
    :pointer # out err_response
  ], KeycloakError.val

  attach_function :keycloak_refresh_token, [
    KeycloakClient.ptr,
    KeycloakToken.val, # refresh token
    :pointer, # scopes
    :int, # scopes len
    KeycloakTokens.ptr, # out tokens
    :pointer # out err_response
  ], KeycloakError.val

  class KeycloakUserinfo < FFI::ManagedStruct
    layout :_json, :pointer,
           :sub, :string,
           :email_verified, :bool,
           :name, :string,
           :preferred_username, :string,
           :given_name, :string,
           :family_name, :string,
           :email, :string

    def sub
      self[:sub]
    end

    def email_verified
      self[:email_verified]
    end

    def name
      self[:name]
    end

    def preferred_username
      self[:preferred_username]
    end

    def given_name
      self[:given_name]
    end

    def family_name
      self[:family_name]
    end

    def email
      self[:email]
    end

    def self.release ptr
      unless ptr.nil?
        Keycloak_FFI.keycloak_destroy_userinfo(ptr)
        FFI::LibC.free(ptr)
      end
    end
  end

  attach_function :keycloak_destroy_userinfo, [:pointer], :void

  attach_function :keycloak_get_userinfo, [
    KeycloakClient.ptr,
    KeycloakTokens.ptr,
    KeycloakUserinfo.ptr, # out
    :pointer # out err_response
  ], KeycloakError.val

  KeycloakJWTValidationResult = enum :VALID, 0,
    :ISS_FAILURE, 1 << 0,
    :SUB_FAILURE, 1 << 1,
    :AUD_FAILURE, 1 << 2,
    :JTI_FAILURE, 1 << 3,
    :EXP_FAILURE, 1 << 4,
    :NBF_FAILURE, 1 << 5,
    :IAT_FAILURE, 1 << 6,
    :SIGNATURE_VERIFICATION_FAILURE, 1 << 7,
    :TYP_FAILURE, 1 << 8

  class KeycloakJWT < FFI::ManagedStruct
    layout :data, :pointer,
           :len, :long

    def [](claim_name)
      claim = KeycloakJWTClaim.new
      Keycloak_FFI.keycloak_jwt_get_claim(
        self,
        claim_name.to_s,
        claim
      )
      return Keycloak._jwt_claim_value(claim)
    end

    def self.release ptr
      unless ptr.nil?
        Keycloak_FFI.keycloak_destroy_jwt(ptr)
        FFI::LibC.free(ptr)
      end
    end
  end

  attach_function :keycloak_destroy_jwt, [:pointer], :void

  enum :KeycloakClaimType, [
    :String, 0,
    :Int, 1,
    :Double, 2,
    :Bool, 3,
    :Null, 4,
    :Array, 5,
    :Object, 6,
    :Other, 7,
  ]

  class KeycloakJWTClaimValue < FFI::Union
    layout :stringvalue, :string,
           :intvalue, :int,
           :doublevalue, :double,
           :boolvalue, :bool,
           :datavalue, :pointer
  end

  class KeycloakJWTClaim < FFI::Struct
    layout :key, :string,
           :value, KeycloakJWTClaimValue.val,
           :type, :KeycloakClaimType
  end

  attach_function :keycloak_jwt_validation_reason_string, [KeycloakJWTValidationResult], :string

  attach_function :keycloak_validate_jwt_ex, [
    KeycloakClient.ptr,
    KeycloakToken.ptr,
    :string, #:validate_iss,
    :int, #:validate_iss_length,
    :string, #:validate_sub,
    :int, #:validate_sub_length,
    :string, #:validate_aud,
    :int, #:validate_aud_length,
    :string, #:validate_jti,
    :int, #:validate_jti_length,
    :string, #:validate_typ,
    :int, #:validate_typ_length,
    :bool, #:validate_exp,
    :int, #:exp_tolerance_seconds,
    :bool, #:validate_nbf,
    :int, #:nbf_tolerance_seconds,
    :bool, #:validate_iat,
    :int, #:iat_tolerance_seconds,
    :pointer # out validation result
  ], KeycloakError.val

  attach_function :keycloak_decode_and_validate_jwt_ex, [
    KeycloakClient.ptr,
    KeycloakToken.ptr,
    :string, # validate_iss,
    :int, # validate_iss_length,
    :string, # validate_sub,
    :int, # validate_sub_length,
    :string, # validate_aud,
    :int, # validate_aud_length,
    :string, # validate_jti,
    :int, # validate_jti_length,
    :string, # validate_typ,
    :int, # validate_typ_length,
    :bool, # validate_exp,
    :int, # exp_tolerance_seconds,
    :bool, # validate_nbf,
    :int, # nbf_tolerance_seconds,
    :bool, # validate_iat,
    :int, # iat_tolerance_seconds,
    :pointer, # KeycloakJWTValidationResult.ptr, # out
    KeycloakJWT.ptr # out
  ], KeycloakError.val

  attach_function :keycloak_jwt_get_claim, [
    KeycloakJWT.ptr,
    :string, # claim key
    KeycloakJWTClaim.ptr # out claim value
  ], KeycloakError.val
end

module Keycloak
  class Error < StandardError
    def initialize(err, str)
      str = FFI::MemoryPointer.new(:string, 1024) # TODO: ERR_MAX macro
      Keycloak_FFI.keycloak_errmsg(err, str)
      super("Error " + err[:errcode].to_s + ": " + str.read_string)
      @ptr = err
    end

    def errcode
      return @ptr[:errcode]
    end
  end

  Tokens = Keycloak_FFI::KeycloakTokens
  Token = Keycloak_FFI::KeycloakToken
  UserInfo = Keycloak_FFI::KeycloakUserinfo

  # TODO: try adding functions to ffi class
  class Client
    def initialize(json, options: 0)
      client_ptr = FFI::LibC.malloc(Keycloak_FFI::KeycloakClient.size)
      @ptr = Keycloak_FFI::KeycloakClient.new(client_ptr)
      err = Keycloak_FFI.keycloak_create_client(@ptr, json, options)
      if err[:errcode] != :OK
        raise Keycloak::Error, err
      end
    end

    def realm
      @ptr[:realm]
    end

    def resource
      @ptr[:resource]
    end

    def auth_server_url
      @ptr[:auth_server_url]
    end

    def secret
      @ptr[:secret]
    end

    def realm_info
      @ptr[:realm_info]
    end

    def get_token(user, pass, scopes: nil)
      tokens_ptr = FFI::LibC.malloc(Keycloak_FFI::KeycloakTokens.size)
      tokens = Keycloak_FFI::KeycloakTokens.new(tokens_ptr)
      err_response_ptr = FFI::MemoryPointer.new(:string)
      scopes_ptr = nil
      scopes_len = 0
      unless scopes.nil?
        scopes_len = scopes.size
        scopes_ptr = FFI::MemoryPointer.new(:pointer, scopes_len)
        ptr_arr = scopes.map do |scope, i|
          ptr = FFI::MemoryPointer.from_string scope
        end
        scopes_ptr.put_array_of_pointer 0, ptr_arr
      end
      err = Keycloak_FFI.keycloak_get_token(
        @ptr,
        user, pass,
        scopes_ptr, scopes_len,
        tokens,
        err_response_ptr
      )

      if err[:errcode] == :HTTP
        err = Keycloak::Error.new(err, err_response_ptr)
        raise err
      elsif err[:errcode] != :OK
        raise Keycloak::Error, err
      end

      return tokens
    end

    def refresh_token(refresh_token, scopes: nil)
      tokens_ptr = FFI::LibC.malloc(Keycloak_FFI::KeycloakTokens.size)
      tokens = Keycloak_FFI::KeycloakTokens.new(tokens_ptr)
      err_response_ptr = FFI::MemoryPointer.new(:string)
      scopes_ptr = nil
      scopes_len = 0
      unless scopes.nil?
        scopes_len = scopes.size
        scopes_ptr = FFI::MemoryPointer.new(:pointer, scopes_len)
        ptr_arr = scopes.map do |scope, i|
          ptr = FFI::MemoryPointer.from_string scope
        end
        scopes_ptr.put_array_of_pointer 0, ptr_arr
      end
      err = Keycloak_FFI.keycloak_refresh_token(
        @ptr,
        refresh_token,
        scopes_ptr, scopes_len,
        tokens,
        err_response_ptr
      )

      if err[:errcode] == :HTTP
        err = Keycloak::Error.new(err, err_response_ptr)
        raise err
      elsif err[:errcode] != :OK
        raise Keycloak::Error, err
      end

      return tokens
    end

    def get_userinfo(tokens)
      userinfo_ptr = FFI::LibC.malloc(Keycloak_FFI::KeycloakUserinfo.size)
      userinfo = Keycloak_FFI::KeycloakUserinfo.new(userinfo_ptr)

      err_response_ptr = FFI::MemoryPointer.new(:string)

      err = Keycloak_FFI.keycloak_get_userinfo(
        @ptr,
        tokens,
        userinfo,
        err_response_ptr
      )

      if err[:errcode] == :HTTP
        err = Keycloak::Error.new(err, err_response_ptr)
        raise err
      elsif err[:errcode] != :OK
        raise Keycloak::Error, err
      end

      return userinfo
    end

    def validate_jwt(
      token,
      # strings
      iss: nil,
      sub: nil,
      aud: nil,
      jti: nil,
      typ: nil,
      # booleans
      validate_exp: false,
      # Tolerance in seconds
      exp_tolerance: 0,
      validate_nbf: false,
      nbf_tolerance: 0,
      validate_iat: false,
      iat_tolerance: 0
    )
      valid = FFI::MemoryPointer.new(:uint8)
      err = Keycloak_FFI.keycloak_validate_jwt_ex(
        @ptr,
        token,
        iss, iss.nil? ? 0 : iss.size,
        sub, sub.nil? ? 0 : sub.size,
        aud, aud.nil? ? 0 : aud.size,
        jti, jti.nil? ? 0 : jti.size,
        typ, typ.nil? ? 0 : typ.size,
        validate_exp, exp_tolerance,
        validate_nbf, nbf_tolerance,
        validate_iat, iat_tolerance,
        valid
      )

      if err[:errcode] != :OK
        raise err
      end

      reason = Keycloak_FFI::KeycloakJWTValidationResult[valid.read(:uint8).to_i]
      return JWTValidationResult.new(
        reason == :VALID,
        reason
      )
    end

    def decode_and_validate_jwt(
      token,
      iss: nil,
      sub: nil,
      aud: nil,
      jti: nil,
      typ: nil,
      validate_exp: false,
      exp_tolerance: 0,
      validate_nbf: false,
      nbf_tolerance: 0,
      validate_iat: false,
      iat_tolerance: 0
    )
      valid = FFI::MemoryPointer.new(:uint8)
      jwt_ptr = FFI::LibC.malloc(Keycloak_FFI::KeycloakJWT.size)
      jwt = Keycloak_FFI::KeycloakJWT.new(jwt_ptr)
      err = Keycloak_FFI.keycloak_decode_and_validate_jwt_ex(
        @ptr,
        token,
        iss, iss.nil? ? 0 : iss.size,
        sub, sub.nil? ? 0 : sub.size,
        aud, aud.nil? ? 0 : aud.size,
        jti, jti.nil? ? 0 : jti.size,
        typ, typ.nil? ? 0 : typ.size,
        validate_exp, exp_tolerance,
        validate_nbf, nbf_tolerance,
        validate_iat, iat_tolerance,
        valid,
        jwt
      )

      if err[:errcode] != :OK
        raise err
      end

      reason = Keycloak_FFI::KeycloakJWTValidationResult[valid.read(:uint8).to_i]
      return JWTDecodeResult.new(
        JWTValidationResult.new(
          reason == :VALID,
          reason
        ),
        jwt
      )
    end
  end

  JWTValidationResult = Struct.new(:valid, :reason) do
    def reason_string
      return Keycloak_FFI.keycloak_jwt_validation_reason_string(self.reason)
    end
  end

  JWTDecodeResult = Struct.new(:valid, :jwt)

  def self._jwt_claim_value claim
    case claim[:type]
    when :String
      return claim[:value][:stringvalue]
    when :Int
      return claim[:value][:intvalue]
    when :Double
      return claim[:value][:doublevalue]
    when :Bool
      return claim[:value][:boolvalue]
    when :Null
      return nil
    # TODO
    when :Array
      return claim[:value][:datavalue]
    when :Object
      return claim[:value][:datavalue]
    when :Other
      return claim[:value][:datavalue]
    end
  end
end
