require 'colorize'

CC = "clang"
CXX = "clang++"

def sh(c)
  puts c.grey
  system c
end

cmd = ARGV.size >= 1 ? ARGV[0] : "build"

unless Dir.exist? "build"
  Dir.mkdir "build"
end

unless Dir.exist? "build/l8w8jwt"
  Dir.mkdir "build/l8w8jwt"
  d = File.realpath("deps/l8w8jwt")
  Dir.chdir "build/l8w8jwt" do
    sh "cmake -DBUILD_SHARED_LIBS=Off -DL8W8JWT_PACKAGE=On -DCMAKE_BUILD_TYPE=Release #{d}"
    sh "cmake --build . --config Release"
  end
end

sources = [
  "deps/cJSON/cJSON.c",
  "deps/str_builder/str_builder.c",
  *Dir["src/**/*.c"],
  *Dir["src/**/*.cpp"],
]

# if cmd == "test"
#   sources << "example.c"
# end

include = [
  "deps",
  "include",
  "build/l8w8jwt/l8w8jwt/include"
]

link = [
  "curl",
  "ssl",
  "crypto",
  "mbedtls",
  "mbedx509",
  "mbedcrypto",
  "l8w8jwt",
]

# Flags
cflags = "-Wno-nullability-completeness"

linker_flags = "-Lbuild/l8w8jwt/l8w8jwt/bin/release -Lbuild/l8w8jwt/mbedtls/Library"
linker_flags << " -l#{link.join " -l"}"
include_flags = "-I#{include.join " -I" }"

build = proc { |type, extra_flags: nil, out: nil|
  # srcs = sources.map { |f| "#{File.basename(f)}"}
  srcs = sources
  out_file = proc { |f|
    "build/#{out.nil? ? "" : "#{out}/"}#{f}"
  }
  obj_file = proc { |f|
    "#{out_file.call File.basename(f)}#{type == :dyn ? ".dyn" : ""}.o"
  }

  for file in srcs
    cc = CC
    if [".cpp", ".c++", ".cxx"].include? File.extname(file)
      cc = CXX
    end
    sh "#{cc} -c \
      #{cc == CXX ? "-std=c++11" : ""} \
      #{extra_flags.nil? ? "" : extra_flags} \
      #{cflags} \
      #{include_flags} \
      #{file} \
      #{type == :dyn ? "-fPIC" : ""} \
      -o #{obj_file.call file}"
  end

  if type == :static
    sh "ar -rcs #{out_file.call "libkeycloak.a"} #{srcs.map {|f| obj_file.call f}.join " "}"
  elsif type == :dyn
    # objs = sources.map { |f| "build/#{File.basename(f)}.dyn.o" }.join " "
    objs = srcs.map{|f| obj_file.call f}.join " "
    sh "#{CC} #{linker_flags} #{objs} -shared -o #{out_file.call "libkeycloak.so"}"
    sh "#{CC} #{linker_flags} #{objs} -dynamiclib -o #{out_file.call "libkeycloak.dylib"}"
  end
}

case cmd
when "build"
  type = ARGV.size == 2 ? ARGV[1] : "static"
  case type
  when "static"
    build.call(:static)
  when "dynamic"
    build.call(:dyn)
  when "test"
    if !Dir.exist?("build/test")
      Dir.mkdir("build/test")
    end
    build.call(:static, extra_flags: "-g", out: "test")
    sh "#{CC} -g #{cflags} -Lbuild/test -lkeycloak -lc++ #{linker_flags} -Iinclude example.c -o build/test/a.out"
  else
    print "invalid command #{type}"
  end
end

if cmd == "test"
  build(:static, extra_flags: "-g", out: "test")
  sh "#{CC} \
    -g \
    #{cflags} \
    #{linker_flags} \
    #{include_flags} \
    #{sources.join " "} -o build/a.out"

  sh "./build/a.out #{ARGV[1...].join " "}"
elsif cmd == "build"
end
