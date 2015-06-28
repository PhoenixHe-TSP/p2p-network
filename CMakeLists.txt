cmake_minimum_required(VERSION 3.2)
project(network)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "/home/htc/dev/p2p-network/test")
set(GCC_COVERAGE_COMPILE_FLAGS "-Wall -Werror -m32 -DDEBUG -std=c11 -D_BSD_SOURCE -D_POSIX_C_SOURCE=199309L")
set(GCC_COVERAGE_LINK_FLAGS    "-lm")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )

set(SOURCE_FILES
    starter_code/bt_parse.c
    starter_code/spiffy.c
    starter_code/debug.c
    starter_code/input_buffer.c
    starter_code/chunk.c
    starter_code/timeout.c
    starter_code/priority_queue.c
    starter_code/bt_io.c
    starter_code/flow.c
    starter_code/sha.c)

add_executable(peer starter_code/peer.c ${SOURCE_FILES} starter_code/task.h starter_code/task.c starter_code/data.h starter_code/data.c starter_code/peer.h starter_code/uthash.h)

