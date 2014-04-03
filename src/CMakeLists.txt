FILE(GLOB SOURCES *.c *.cpp)

GET_FILENAME_COMPONENT(MAIN_SOURCE "main.cpp" ABSOLUTE)
LIST(REMOVE_ITEM SOURCES "${MAIN_SOURCE}")
ADD_LIBRARY(asymmetric ${SOURCES})

ADD_EXECUTABLE(asymmetricfs "${MAIN_SOURCE}")

TARGET_LINK_LIBRARIES(asymmetricfs asymmetric boost_thread boost_program_options boost_system ${FUSE})
