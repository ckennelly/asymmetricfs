FILE(GLOB SOURCES *.c *.cpp)

GET_FILENAME_COMPONENT(MAIN_SOURCE "main.cpp" ABSOLUTE)
LIST(REMOVE_ITEM SOURCES "${MAIN_SOURCE}")
ADD_LIBRARY(asymmetric ${SOURCES})
TARGET_LINK_LIBRARIES(asymmetric boost_program_options boost_thread boost_system)

ADD_EXECUTABLE(asymmetricfs "${MAIN_SOURCE}")

TARGET_LINK_LIBRARIES(asymmetricfs asymmetric boost_program_options ${FUSE})

INCLUDE_DIRECTORIES(.)
ADD_SUBDIRECTORY(test)
