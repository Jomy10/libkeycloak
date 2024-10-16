require_relative 'bindings/ruby/keycloak.rb'

if ARGV.size != 2
  STDERR << "Usage: #{$0} [user] [password]\n"
  exit 1
end

user = ARGV[0]
pass = ARGV[1]

# Create a client from the json config
puts "Retrieving client..."
client = Keycloak::Client.new(File.read("keycloak.json"))
puts client.resource

# Login with email and password and get a token
# "openid" scope required for userinfo endpoint
puts "Retrieving token..."
tokens = client.get_token(user, pass, scopes: ["openid"])
puts "token: #{tokens.access_token.token}"

puts "Refreshing token..."
tokens = client.refresh_token(tokens.refresh_token, scopes: ["openid"])
puts "refreshed token: #{tokens.access_token.token}"

puts "Getting userinfo..."
userinfo = client.get_userinfo(tokens)
puts "Username: #{userinfo.preferred_username}"

puts "Validating token..."
valid = client.validate_jwt(
  tokens.access_token,
  validate_exp: true
)
if valid.valid
  puts "token valid!"
else
  puts "token invalid: #{valid.reason_string}"
end

puts "Decoding and reading jwt..."
jwt_res = client.decode_and_validate_jwt(
  tokens.access_token,
  validate_exp: true
)
if !jwt_res.valid.valid
  puts "token invalid: #{jwt_res.valid.reason_string}"
end

jwt = jwt_res.jwt

puts "iss = #{jwt["iss"]}"
