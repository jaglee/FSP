# CMakeList.txt : CMake project for FSP_LLS
#
# cmake_minimum_required (VERSION 3.6)
project(FSP_LLS VERSION 0.1)

# add_definitions(-DDEBUG_ICC)
add_executable(fsp_lls "main.cpp" "os_linux.cpp"
   "command.cpp" "mobile.cpp"  "remote.cpp" "socket.cpp" "timers.cpp"
   ../ControlBlock.cpp
   "blake2b.c" "CRC64.c" "gcm-aes.c" "rijndael-alg-fst.c")
target_link_libraries(fsp_lls PUBLIC ${EXTRA_LIBS})
