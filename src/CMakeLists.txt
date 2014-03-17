FILE(GLOB SOURCES *.c *.cpp)
ADD_EXECUTABLE(asymmetricfs ${SOURCES})

TARGET_LINK_LIBRARIES(asymmetricfs boost_thread boost_program_options
boost_system ${FUSE})
