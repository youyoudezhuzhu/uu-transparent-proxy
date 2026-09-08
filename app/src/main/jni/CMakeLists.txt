cmake_minimum_required(VERSION 3.22.1)
project(uuproxy C)

set(CMAKE_C_STANDARD 11)

# Native transparent-proxy daemon (JNI), self-contained, no external deps.
add_library(uuproxy SHARED
        native-lib.c
        )

find_library(log-lib log)

target_link_libraries(uuproxy
        ${log-lib}
        )

# redsocks/redsocks2 reference source is vendored under third_party/redsocks.
# It is NOT compiled into the APK (it depends on libevent); it is kept as an
# authoritative reference for the transparent->SOCKS5/HTTP algorithm. See README.
