# CMakeList.txt : CMake project for CMakeFSPLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# FSP is in preliminary stage, only debug version is provided as is
add_definitions(-DOVER_UDP_IPv4 -D_DEBUG -DTRACE)
add_compile_options(-pthread -Wall -Werror -Wno-error=unused-value)

add_subdirectory(FSP_DLL)

list(APPEND EXTRA_LIBS FSPLib)
list(APPEND EXTRA_LIBS rt)
list(APPEND EXTRA_LIBS pthread)

add_executable(RawMemoryServer
                RawMemoryServer/RawMemoryServer.cpp RawMemoryServer/MemoryFile.cpp
                Crypto/CryptoStub.c Crypto/sha256.c Crypto/tweetnacl.c)
target_link_libraries(RawMemoryServer PUBLIC ${EXTRA_LIBS})


add_definitions(-D_DEBUG_PEEK)
add_executable(FSP_HTTP
                FSP_HGW/httpd.cpp FSP_HGW/RequestPool.cpp FSP_HGW/tunnel.cpp
                FSP_HGW/fcgi.cpp 
                Crypto/CryptoStub.c Crypto/sha256.c Crypto/tweetnacl.c)
target_link_libraries(FSP_HTTP PUBLIC ${EXTRA_LIBS})
