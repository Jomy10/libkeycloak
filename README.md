# Keycloak C

A wrapper for the Keycloak API in C. Includes some bindings for different languages

## Usage

### Installation

#### C

see [Building](#building).

#### Ruby

- Install the C library as a [dynamic library](dynamic-library)
- Include the ruby file at `bindings/ruby/keycloak.rb` in your project

<!-- - OR: `gem install keycloak-api` -->

## Building

You need Ruby and the colorize gem (`gem install colorize`)

### Static library

```sh
ruby build.rb build static
```

There is only one header to be included, located at src/keycloak.h

### Dynamic library

```sh
ruby build.rb build dynamic
```

The dynamc libraries are now located in the `build` folder. Copy them to a folder
in `echo $LD_LIBRARY_PATH`.

## Keycloak.json

The file `keycloak.json` is required by the library, you can obtain it from going to a Client in the Keycloak console
and clicking "action" > "Download adapter config" and choose JSON.

In settings, make sure "Client authentication" is turned on.

## Examples

### Ruby

- Request a token for a user
```ruby
require 'JSON'
require_relative 'keycloak.rb'

client = Keycloak::Client.new(File.read("keycloak.json"))
token = client.get_token("username", "password")
if token.status_code == 200
  puts JSON.parse(token.response)["access_token"]
else
  puts "Got HTTP code #{token.status_code}, response: #{token.response}"
end
```

### C

- Request a token for a user

See [example.c](example.c).
