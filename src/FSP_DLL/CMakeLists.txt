# CMakeList.txt : CMake project for CMakeFSPLib, include source and define
# project specific logic here.
#
# cmake_minimum_required (VERSION 3.8)
# include these options in the top level CMakeList.txt
# add_compile_options(-pthread -Wall -Werror -Wno-error=unused-value -D OVER_UDP_IPv4)
# TO exploit SHARED library later

add_library (FSPLib LibEntry.cpp
             Deflate.cpp Disconnect.cpp Establish.cpp IOControl.cpp Multiplex.cpp Receive.cpp Send.cpp
             lz4.c
            ../ControlBlock.cpp)
target_link_libraries(FSPLib PUBLIC ${EXTRA_LIBS})
