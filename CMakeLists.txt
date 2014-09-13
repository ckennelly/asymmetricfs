CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# Boost.  We require version 1.49 or higher due to:
# http://stackoverflow.com/questions/11302758/error-while-copy-constructing-boostshared-ptr-using-c11
FIND_PACKAGE(Boost 1.49 REQUIRED program_options system)

# FUSE
FIND_LIBRARY(FUSE "fuse")

# Warnings
SET(WARNINGS "-Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wredundant-decls -Winline -Wuninitialized -Wno-conversion -Wno-sign-conversion -Werror -Wno-missing-field-initializers -Wno-sign-compare")
SET(CMAKE_CXX_FLAGS "${WARNINGS} -Wnon-virtual-dtor -g")

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

# xattr support
CHECK_INCLUDE_FILE_CXX("attr/xattr.h" HAS_XATTR)
IF (HAS_XATTR)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAS_XTTR")
ENDIF()

# GPG binary path, used for defaults.
FIND_PROGRAM(GPG_PATH "gpg")
IF (GPG_PATH)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} '-DGPG_PATH=${GPG_PATH}'")
ENDIF()

# Google Test
ADD_SUBDIRECTORY(third_party/googletest)
INCLUDE_DIRECTORIES(SYSTEM third_party/googletest/include)

# Build targets
ENABLE_TESTING()
ADD_SUBDIRECTORY(src)
