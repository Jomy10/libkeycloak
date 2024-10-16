Gem::Specification.new do |s|
  s.name = "libkeycloak"
  s.version = "1.0.1"
  s.summary = "A library for interacting with Keycloak and validating jwt tokens returned from it."
  s.description = <<~DESCRIPTION
  == libkeycloak for Ruby

  This gem is a wrapper around libkeycloak (https://github.com/Jomy10/libkeycloak) to interact with the Keycloak API.
  It also includes functions for verifying tokens. Examples can be found in the git repository.

  == Installation

  The C library should be built and installed as a dynamic library first, see https://github.com/Jomy10/libkeycloak?tab=readme-ov-file#dynamic-library
  DESCRIPTION
  # s.extra_rdoc_files << File.join(Dir.pwd, "../../README.md")
  s.authors = ["Jonas Everaert"]
  s.files = "keycloak.rb"
  s.homepage = "https://github.com/Jomy10/libkeycloak"
  s.license = "MIT"
  s.add_dependency "ffi", "~> 1.17"
  s.add_dependency "ffi-libc", "~> 0.1"
  s.required_ruby_version = ">= 2.5" # from ffi
end
