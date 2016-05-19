cmake_minimum_required(VERSION 2.8)
project (petya_green)

set (hdrs
    petya.h
    salsa20.h
    util.h
    )

set (srcs
    salsa20.cpp
    main.cpp
    petya.cpp
    util.cpp
    )

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

IF (NOT APPLE)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBRARIES OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
ENDIF(NOT APPLE)

option (OUT_32BIT "Build 32-bit executable" OFF)

IF (OUT_32BIT)
    # To build x86 executable on x86-64 linux, install also the following: gcc-multilib g++-multilib
    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR "i686")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" CACHE STRING "c++ flags")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m32" CACHE STRING "c flags")
ENDIF(OUT_32BIT)

add_executable (petya_green ${hdrs} ${srcs})

