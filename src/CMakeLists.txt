# Clang supports -Weverything, which allows us to pick up on potentially
# overlooked warning options that aren't set by -Wall/-Wextra.
IF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    ADD_COMPILE_OPTIONS("-Weverything")

    # asymmetricfs targets C++11 and above.
    ADD_COMPILE_OPTIONS("-Wno-c++98-compat")
    ADD_COMPILE_OPTIONS("-Wno-c++98-compat-pedantic")

    # Suppress uninteresting warnings.
    ADD_COMPILE_OPTIONS("-Wno-exit-time-destructors")
    ADD_COMPILE_OPTIONS("-Wno-padded")
    ADD_COMPILE_OPTIONS("-Wno-weak-vtables")

    # Test cases using Google Test run into these warnings.
    ADD_COMPILE_OPTIONS("-Wno-global-constructors")
    ADD_COMPILE_OPTIONS("-Wno-missing-prototypes")
    ADD_COMPILE_OPTIONS("-Wno-missing-variable-declarations")
    ADD_COMPILE_OPTIONS("-Wno-used-but-marked-unused")

    # GCC chokes when we compile code that has had unreachable code as it does
    # not reach a similar conclusion.
    ADD_COMPILE_OPTIONS("-Wno-unreachable-code")
ENDIF()

FILE(GLOB SOURCES *.c *.cpp)

GET_FILENAME_COMPONENT(MAIN_SOURCE "main.cpp" ABSOLUTE)
LIST(REMOVE_ITEM SOURCES "${MAIN_SOURCE}")
ADD_LIBRARY(asymmetric ${SOURCES})
TARGET_LINK_LIBRARIES(asymmetric boost_program_options boost_system)

ADD_EXECUTABLE(asymmetricfs "${MAIN_SOURCE}")

TARGET_LINK_LIBRARIES(asymmetricfs asymmetric boost_program_options ${FUSE})

INCLUDE_DIRECTORIES(.)
ADD_SUBDIRECTORY(test)
