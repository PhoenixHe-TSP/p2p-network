cmake_minimum_required(VERSION 3.2)
project(network)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    starter_code/bt_parse.c
    starter_code/spiffy.c
    starter_code/debug.c
    starter_code/input_buffer.c
    starter_code/chunk.c
    starter_code/sha.c)


add_executable(peer starter_code/peer.c ${SOURCE_FILES})

add_executable(make-chunks starter_code/make_chunks.c starter_code/chunk.c starter_code/sha.c)

add_executable(test-input-buffer starter_code/test_input_buffer.c starter_code/input_buffer.c)
