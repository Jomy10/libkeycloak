require 'colorize'

CC = "clang"

def sh(c)
  puts c.grey
  system c
end

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

linker_flags = "-l#{link.join " -l"}"
include_flags = "-I#{include.join " -I" }"

if cmd == "test"
  sh "#{CC} \
    #{linker_flags} \
    #{include_flags} \
    #{sources.join " "} -o build/a.out"

  sh "./build/a.out #{ARGV[1...].join " "}"
elsif cmd == "build"
  type = ARGV.size == 2 ? ARGV[1] : "static"

  build_objs = proc { |ty|
    for file in sources
      sh "#{CC} -c \
        #{include_flags} \
        #{file} \
        #{ty == :dyn ? "-fPIC" : ""} \
        -o build/#{File.basename(file)}#{ty == :dyn ? ".dyn" : ""}.o"
    end
  }

  if type == "static"
    build_objs.call()
    sh "ar -rcs build/libkeycloak.a #{sources.map { |f| "build/#{File.basename(f)}.o"}.join " "}"
  elsif type == "dynamic"
    build_objs.call(:dyn)
    objs = sources.map { |f| "build/#{File.basename(f)}.dyn.o" }.join " "
    sh "#{CC} #{linker_flags} #{objs} -shared -o build/libkeycloak.so"
    sh "#{CC} #{linker_flags} #{objs} -dynamiclib -o build/libkeycloak.dylib"
  end
end
