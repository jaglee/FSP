# CMakeList.txt : CMake project for FSP_LLS, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project(FSP_LLS VERSION 0.1)

## -DTRACE=58 -DDEBUG_ICC
add_definitions(-DOVER_UDP_IPv4 -D_DEBUG -DTRACE=16)
add_compile_options(-g -pthread -Wall -Werror -Wno-error=unused-value)

# Add source to this project's executable.
add_executable(fsp_lls "main.cpp" "os_linux.cpp"
   "command.cpp" "mobile.cpp"  "remote.cpp" "socket.cpp" "timers.cpp"
   ../ControlBlock.cpp
   "blake2b.c" "CRC64.c" "gcm-aes.c" "rijndael-alg-fst.c")

target_link_libraries(fsp_lls -lrt -lpthread)
