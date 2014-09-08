CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Boost
FIND_PACKAGE(Boost REQUIRED program_options system)

# FUSE
FIND_LIBRARY(FUSE "fuse")

# Warnings
SET(WARNINGS "-Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wredundant-decls -Winline -Wno-long-long -Wuninitialized -Wconversion -Wno-sign-conversion -Werror")
SET(CMAKE_CXX_FLAGS "${WARNINGS} -Wabi -Wnon-virtual-dtor -g")

# C++11 support
INCLUDE(TestCXXAcceptsFlag)
CHECK_CXX_ACCEPTS_FLAG("-std=c++11" USE11FLAG)
CHECK_CXX_ACCEPTS_FLAG("-std=c++0x" USE0xFLAG)
IF(USE11FLAG)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
ELSEIF(USE0xFLAG)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
ELSE()
    MESSAGE(ERROR "C++0x/C++11 support is required.")
ENDIF()

# Valgrind support, for annotations.
INCLUDE(CheckIncludeFileCXX)
CHECK_INCLUDE_FILE_CXX("valgrind/memcheck.h" HAS_VALGRIND)
IF (HAS_VALGRIND)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAS_VALGRIND")
ENDIF()

# Build targets
ENABLE_TESTING()
ADD_SUBDIRECTORY(src)
