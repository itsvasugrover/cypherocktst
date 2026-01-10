cmake_minimum_required(VERSION 3.15)
project(Server C CXX)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/nanopb/extra ${CMAKE_MODULE_PATH})

find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
find_package(Nanopb REQUIRED)

set(CRYPTO_DIR ${CMAKE_SOURCE_DIR}/lib/crypto)
include_directories(${CRYPTO_DIR})

set(CRYPTO_SOURCES
    ${CRYPTO_DIR}/bignum.c
    ${CRYPTO_DIR}/ecdsa.c
    ${CRYPTO_DIR}/curves.c
    ${CRYPTO_DIR}/secp256k1.c
    ${CRYPTO_DIR}/rand.c
    ${CRYPTO_DIR}/hmac.c
    ${CRYPTO_DIR}/ripemd160.c
    ${CRYPTO_DIR}/sha2.c
    ${CRYPTO_DIR}/sha3.c
    ${CRYPTO_DIR}/memzero.c
    ${CRYPTO_DIR}/hasher.c
    ${CRYPTO_DIR}/address.c
    ${CRYPTO_DIR}/base58.c
    ${CRYPTO_DIR}/rfc6979.c
    ${CRYPTO_DIR}/hmac_drbg.c
    ${CRYPTO_DIR}/blake256.c
    ${CRYPTO_DIR}/blake2b.c
    ${CRYPTO_DIR}/groestl.c
)

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/../proto/comms.proto")
set(PROTO_OUT_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_OUT_DIR})

nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS RELPATH "${CMAKE_SOURCE_DIR}/../proto" ${PROTO_FILE})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR})
include_directories(${PROTO_OUT_DIR})

add_executable(server 
    src/main.cpp
    src/server.cpp
    ${CRYPTO_SOURCES}
    ${PROTO_SRCS}
)

target_link_libraries(server
    nanopb
)

set_property(TARGET server PROPERTY CXX_STANDARD 17)