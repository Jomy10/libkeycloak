#!~/.rubies/ruby-3.2.2/bin/ruby

cmd = ARGV.size >= 1 ? ARGV[0] : "build"

unless Dir.exist? "build"
  Dir.mkdir "build"
end

sources = [
  "deps/cJSON/cJSON.c",
  "deps/str_builder/str_builder.c",
  *Dir["src/*.c"]
]

if cmd == "test"
  sources << "example.c"
end

include = [
  "deps"
]

link = [
  "curl"
]

sh = "clang \
  -l#{link.join " -l"} \
  -I#{include.join " -I" } \
  #{sources.join " "} "

if cmd == "test"
  sh << "-o build/a.out"
end

puts sh
system sh

if cmd == "test"
  sh = "./build/a.out #{ARGV[1...].join " "}"
  puts sh
  exec sh
end
