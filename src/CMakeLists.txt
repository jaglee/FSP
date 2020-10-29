# CMakeList.txt : CMake project for Flexible Session Protocol
#
cmake_minimum_required (VERSION 3.6)
project(Flexible_Session_Protocol VERSION 0.1)

# FSP is in preliminary stage, only debug/trace version is provided as is
if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
	message("Generation build type Debug")
	add_definitions(-D_DEBUG -DTRACE=20)
	add_compile_options(-g)
else()
	message("Generation build type Release")
	add_definitions(-DTRACE)	# -DNDEBUG
	add_compile_options(-O2)
endif()

add_definitions(-DOVER_UDP_IPv4)
add_compile_options(-pthread -Wall -Werror -Wno-error=unused-value -Wno-strict-aliasing)

if(${MINGW})
    list(APPEND EXTRA_LIBS Ws2_32)
else()
    list(APPEND EXTRA_LIBS rt)
    list(APPEND EXTRA_LIBS pthread)
endif()

add_subdirectory(FSP_DLL)

add_subdirectory(FSP_SRV)

list(APPEND EXTRA_LIBS FSPLib)

add_executable(TestHGW
                Test_HGW/TestHGW.cpp Test_HGW/UnitTest.cpp
                FSP_HGW/RequestPool.cpp)
target_link_libraries(TestHGW PUBLIC ${EXTRA_LIBS})

add_definitions(-D_DEBUG_PEEK)

add_executable(FSP_HTTP
				FSP_HGW/httpd.cpp FSP_HGW/RequestPool.cpp FSP_HGW/tunnel.cpp
				FSP_HGW/fcgi.cpp 
				Crypto/CryptoStub.c Crypto/sha256.c Crypto/tweetnacl.c)
target_link_libraries(FSP_HTTP PUBLIC ${EXTRA_LIBS})

add_executable(FSP_SOCKS
				FSP_HGW/SOCKSv5.cpp FSP_HGW/RequestPool.cpp FSP_HGW/tunnel.cpp
				Crypto/CryptoStub.c Crypto/sha256.c Crypto/tweetnacl.c)
target_link_libraries(FSP_SOCKS PUBLIC ${EXTRA_LIBS})
