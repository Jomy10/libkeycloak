# Keycloak C

A wrapper for the Keycloak API in C. Includes some bindings for different languages

## Usage

### Installation

#### C

see [Building](#building).

#### Ruby [![Gem Version](https://badge.fury.io/rb/libkeycloak.svg)](https://badge.fury.io/rb/libkeycloak)

- Install the C library as a [dynamic library](#dynamic-library)
- Install the gem
```sh
gem install libkeycloak
```

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

To run the examples, you need a keycloak.json. You can obtain it from going to a Client in the Keycloak console
and clicking "action" > "Download adapter config" and choose JSON.

Paste the file in the root of this repository to try out the examples.

All the example code can be found in the root of this repository as `example.[lang]`.

The `[user]` and `[pass]` arguments are used to log in to a user in the keycloak realm specified by the `keycloak.json`.

### C

```sh
ruby build.rb test
./build/test/a.out [user] [pass]
```

### Ruby

```sh
ruby build.rb build dynamic
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$(pwd)/build" ruby example.rb [user] [pass]
# OR: copy the dynamic library to a path in LD_LIBRARY_PATH
```

## Questions

Feel free to ask any questions regarding the library as an issue.

## License

Licensed under the [MIT license](LICENSE).
