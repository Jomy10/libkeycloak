require 'ffi'

module Keycloak_FFI
  extend FFI::Library

  ffi_lib 'c'

  attach_function :free, [:pointer], :void

  ffi_lib 'keycloak'

  class KeycloakClient < FFI::Struct
    layout :json_obj, :pointer,
           :realm, :string,
           :resource, :string,
           :auth_server_url, :string,
           :secret, :string
  end

  attach_function :keycloak_client_init_from_json, [:pointer, :string], :int
  attach_function :keycloak_client_deinit, [:pointer], :void
  attach_function :keycloak_get_token, [
    :pointer,
    :string,
    :string,
    :pointer,
    :pointer
  ], :int
end



module Keycloak
  Response = Struct.new(:response, :status_code)

  class Client
    def initialize(json)
      @ptr = Keycloak_FFI::KeycloakClient.new
      if Keycloak_FFI.keycloak_client_init_from_json(@ptr, json) != 0
        raise "Couldn't create client"
      end
    end

    def get_token(user, password)
      response_ptr = FFI::MemoryPointer.new(:pointer)
      http_status_code_ptr = FFI::MemoryPointer.new(:long)

      ret = Keycloak_FFI.keycloak_get_token(
        @ptr,
        user, password,
        response_ptr, http_status_code_ptr)
      if ret != 0
        raise "Error executing HTTP request"
      end

      response_str_ptr = response_ptr.read(:pointer)
      response = response_str_ptr.read_string
      http_status_code = http_status_code_ptr.read(:long)

      Keycloak_FFI.free(response_str_ptr)

      return Response.new(response, http_status_code)
    end

    def close
      Keycloak_FFI.client_deinit(@ptr)
    end
  end
end
